package api

import (
	"context"
	"net/http"
	"sync"
)

type Handler struct {
	BaseContext      func() context.Context
	JWKSURL          string
	ExpectedIssuer   string
	ExpectedAudience string

	once    sync.Once
	handler http.Handler
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.once.Do(func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/subject", h.subject)
		h.handler = h.withAuth(mux)
	})

	h.handler.ServeHTTP(w, r)
}
