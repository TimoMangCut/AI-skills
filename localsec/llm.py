from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class LocalModelError(RuntimeError):
    pass


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Avoid ambient proxy settings: source excerpts must not silently traverse a proxy.
_NO_REDIRECT_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirectHandler())


def assert_local_endpoint(base_url: str, allow_remote: bool) -> None:
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise LocalModelError("LLM base_url must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise LocalModelError("Do not embed credentials in llm.base_url")
    if allow_remote:
        return
    host = parsed.hostname.lower().strip("[]")
    if host == "localhost" or host.endswith(".localhost"):
        return
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
        is_loopback = bool(infos) and all(info[4][0].split("%", 1)[0] in {"127.0.0.1", "::1"} for info in infos)
    except OSError:
        is_loopback = False
    if not is_loopback:
        raise LocalModelError(f"Refusing non-loopback LLM endpoint {base_url!r}; set llm.allow_remote=true only after explicit data-handling review")


class OpenAICompatibleLocalClient:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.base_url = str(config.get("base_url", "http://127.0.0.1:11434/v1")).rstrip("/")
        self.model = os.environ.get("LOCALSEC_MODEL", str(config.get("model", ""))).strip()
        if not self.model:
            raise LocalModelError("No model configured. Set llm.model or LOCALSEC_MODEL.")
        assert_local_endpoint(self.base_url, bool(config.get("allow_remote", False)))

    def probe(self) -> tuple[bool, str]:
        url = f"{self.base_url}/models"
        req = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
        try:
            with _NO_REDIRECT_OPENER.open(req, timeout=min(8, int(self.config.get("timeout_seconds", 180)))) as response:
                if response.status < 400:
                    return True, "local endpoint responds"
                return False, f"HTTP status {response.status}"
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"

    def complete_json_messages(self, system_prompt: str, messages: list[dict[str, str]]) -> dict[str, Any]:
        url = f"{self.base_url}/chat/completions"
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system_prompt}, *messages],
            "temperature": float(self.config.get("temperature", 0.0)),
            "max_tokens": int(self.config.get("max_tokens", 7000)),
            "response_format": {"type": "json_object"},
            "stream": False,
        }
        req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers={"Content-Type": "application/json", "Accept": "application/json"}, method="POST")
        try:
            with _NO_REDIRECT_OPENER.open(req, timeout=int(self.config.get("timeout_seconds", 180))) as response:
                response_body = response.read(30_000_000)
            envelope = json.loads(response_body.decode("utf-8"))
            content = envelope["choices"][0]["message"]["content"]
            if isinstance(content, list):
                content = "".join(str(part.get("text", "")) if isinstance(part, dict) else str(part) for part in content)
            return self._parse_json(str(content))
        except urllib.error.HTTPError as exc:
            detail = exc.read(4000).decode("utf-8", errors="replace")
            raise LocalModelError(f"Local LLM HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise LocalModelError(f"Cannot reach local LLM endpoint: {exc.reason}") from exc
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            raise LocalModelError(f"Unexpected LLM response format: {exc}") from exc
        except TimeoutError as exc:
            raise LocalModelError("Local LLM request timed out") from exc

    def complete_json(self, system_prompt: str, user_payload: dict[str, Any]) -> dict[str, Any]:
        return self.complete_json_messages(system_prompt, [{"role": "user", "content": json.dumps(user_payload, ensure_ascii=False, separators=(",", ":"))}])

    @staticmethod
    def _parse_json(content: str) -> dict[str, Any]:
        content = content.strip()
        if content.startswith("```"):
            lines = content.splitlines()
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            content = "\n".join(lines).strip()
        try:
            value = json.loads(content)
        except json.JSONDecodeError:
            first, last = content.find("{"), content.rfind("}")
            if first < 0 or last <= first:
                raise LocalModelError("Model did not return a JSON object")
            value = json.loads(content[first:last + 1])
        if not isinstance(value, dict):
            raise LocalModelError("Model output must be a JSON object")
        return value
