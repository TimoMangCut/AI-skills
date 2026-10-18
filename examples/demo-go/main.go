package main

import (
    "net/http"
    "time"
)

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("GET /health", healthHandler)
    server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 3 * time.Second}
    _ = server.ListenAndServe()
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    _, _ = w.Write([]byte("ok"))
}
