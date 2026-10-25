# Web Apps, SPAs (React/Next.js/Angular/Vue), SSR & Low-Code (`web-spa-nextjs-ssr`)

> **Group:** I. Web, Mobile & API Core
> **Product Archetypes:** SPA_Web_Frontend, Fullstack_Web_App, Ecommerce_Portal, LowCode_Admin_Portal
> **Trigger Signals:** react, nextjs, next, angular, vue, webpack, vite, sourcemap, ssr, nocobase, wordpress, php, spa, cors, csrf, xss

## [ BLOCK: nextjs-ssr-and-server-actions ]
### Next.js App/Pages Router, SSR Data Leaks & Server Actions
- Inspect `getServerSideProps`, React Server Components (RSC), and Server Actions (`'use server'`) for missing session/role checks.
- Verify whether full internal objects or admin routes (e.g., 900+ client routes in Next.js manifests) leak sensitive tenant/dealer logic or internal API base URLs.
- Check middleware bypass (`middleware.ts` matcher gaps, `x-middleware-subrequest`, path normalization).

## [ BLOCK: spa-sourcemap-and-bundle-secrets ]
### SPA Sourcemaps (.js.map), Environment Configs & Client-Side Auth Bypass
- Check build configs (`productionBrowserSourceMaps`, Vite/Webpack/Angular `sourceMap`) for `.js.map` exposure in prod/staging buckets.
- Inspect `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, and `config.js` for leaked internal API gateways (`emp-non-prod-api`, OAuth client secrets, static HMAC keys).
- Enforce the H5 200-Falsehood rule: distinguish real asset/API responses from SPA `index.html` catch-all rewrites.

## [ BLOCK: dom-xss-postmessage-and-cors ]
### DOM XSS, postMessage Bridges, OAuth Redirects & Permissive CORS
- Trace `window.addEventListener('message', ...)` handlers without strict `event.origin` verification.
- Audit `Access-Control-Allow-Origin` reflection and staging/localhost origins (`http://localhost:3003`) enabled with `Access-Control-Allow-Credentials: true`.
- Verify OAuth/OIDC `redirect_uri`, `state`, and PKCE validation against open-redirect token theft.
