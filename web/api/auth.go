package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

type ctxKey string

const ctxKeySubject ctxKey = "subject"

func (h *Handler) withAuth(next http.Handler) http.Handler {
	refresher := jwk.NewAutoRefresh(h.BaseContext())
	refresher.Configure(h.JWKSURL)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		authorization := r.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, "Bearer ") {
			next.ServeHTTP(w, r)
			return
		}

		provider := jwt.KeySetProviderFunc(func(jwt.Token) (jwk.Set, error) {
			return refresher.Fetch(ctx, h.JWKSURL)
		})
		tok, err := jwt.ParseString(authorization[7:],
			jwt.WithPedantic(true),
			jwt.WithKeySetProvider(provider),
		)
		if err != nil {
			fmt.Printf("auth error: %v\n", err)
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}

		err = jwt.Validate(tok,
			jwt.WithContext(ctx),
			jwt.WithIssuer(h.ExpectedIssuer),
			jwt.WithAudience(h.ExpectedAudience),
		)
		if err != nil {
			fmt.Printf("auth error: %v\n", err)
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}

		ctx = contextWithSubject(ctx, tok.Subject())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func contextWithSubject(ctx context.Context, subject string) context.Context {
	return context.WithValue(ctx, ctxKeySubject, subject)
}

func subjectFromContext(ctx context.Context) (string, bool) {
	subject, ok := ctx.Value(ctxKeySubject).(string)
	return subject, ok
}

func (h *Handler) subject(w http.ResponseWriter, r *http.Request) {
	subject, ok := subjectFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}

	fmt.Fprintln(w, subject)
}
