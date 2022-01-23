package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

func genRSAPrivateKey(t *testing.T) *rsa.PrivateKey {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func setupTestJWKSServer(t *testing.T, key *rsa.PrivateKey) *httptest.Server {
	t.Helper()

	set, err := jwk.New(key)
	if err != nil {
		t.Fatal(err)
	}

	set.Set(jwk.KeyIDKey, "test-kid")
	set.Set(jwk.AlgorithmKey, jwa.RS256)

	priv, ok := set.(jwk.RSAPrivateKey)
	if !ok {
		t.Fatalf("expected %T to be an RSA private key", set)
	}

	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	raw, err := json.Marshal(pub)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write(raw)
		if err != nil && !errors.Is(err, syscall.EPIPE) {
			t.Log(err)
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return srv
}

func setupTestServer(t *testing.T, priv *rsa.PrivateKey) *httptest.Server {
	jwksServer := setupTestJWKSServer(t, priv)

	h := &Handler{
		BaseContext:      func() context.Context { return context.Background() },
		JWKSURL:          jwksServer.URL + "/.well-known/jwks.json",
		ExpectedIssuer:   "test-issuer",
		ExpectedAudience: "test-audience",
	}

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	return srv
}

func genBearerToken(t *testing.T, priv *rsa.PrivateKey, updater func(b *jwt.Builder)) string {
	t.Helper()

	now := time.Now()
	exp := now.Add(time.Hour)
	builder := jwt.NewBuilder().
		Subject("test-subject").
		Audience([]string{"test-audience"}).
		Issuer("test-issuer").
		Expiration(exp).
		IssuedAt(now).
		NotBefore(now)

	if updater != nil {
		updater(builder)
	}

	tok, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}

	headers := jws.NewHeaders()
	headers.Set(jws.KeyIDKey, "test-kid")

	b, err := jwt.Sign(tok, jwa.RS256, priv, jwt.WithHeaders(headers))
	if err != nil {
		t.Fatal(err)
	}

	return string(b)
}

func Test_subjectHandler(t *testing.T) {
	priv := genRSAPrivateKey(t)
	srv := setupTestServer(t, priv)

	req, err := http.NewRequest("GET", srv.URL+"/subject", nil)
	if err != nil {
		t.Error(err)
		return
	}

	t.Run("unauthenticated", func(t *testing.T) {
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Error(err)
			return
		}

		if want, got := http.StatusUnauthorized, resp.StatusCode; want != got {
			t.Errorf("want status code %d, got %d", want, got)
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Error(err)
			return
		}

		defer resp.Body.Close()

		if want, got := "unauthenticated", string(bytes.TrimSpace(body)); want != got {
			t.Errorf("want body %q, got %q", want, got)
			return
		}
	})

	t.Run("ok", func(t *testing.T) {
		wantSubject := "random-test-subject"
		accessToken := genBearerToken(t, priv, func(b *jwt.Builder) {
			b.Subject(wantSubject)
		})
		req.Header.Set("Authorization", "Bearer "+accessToken)

		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Error(err)
			return
		}

		defer resp.Body.Close()

		if want, got := http.StatusOK, resp.StatusCode; want != got {
			t.Errorf("want status code %d, got %d", want, got)
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Error(err)
			return
		}

		if want, got := wantSubject, string(bytes.TrimSpace(body)); want != got {
			t.Errorf("want body %q, got %q", want, got)
			return
		}
	})
}
