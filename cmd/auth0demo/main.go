package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"

	dotenv "github.com/joho/godotenv"
	"github.com/nicolasparada/go-auth0-demo/web/api"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	_ = dotenv.Load()

	var (
		port        = env("PORT", "4000")
		jwksURL     = os.Getenv("JWKS_URL")
		expectedIss = os.Getenv("EXPECTED_ISSUER")
		expectedAud = os.Getenv("EXPECTED_AUDIENCE")
	)

	fs := flag.NewFlagSet("auth0demo", flag.ExitOnError)
	fs.StringVar(&port, "port", port, "Port to listen on")
	fs.StringVar(&jwksURL, "jwks-url", jwksURL, "JWKS URL")
	fs.StringVar(&expectedIss, "expected-issuer", expectedIss, "Expected issuer")
	fs.StringVar(&expectedAud, "expected-audience", expectedAud, "Expected audience")
	err := fs.Parse(os.Args[1:])
	if err != nil {
		return err
	}

	h := &api.Handler{
		BaseContext: func() context.Context {
			return context.Background()
		},
		JWKSURL:          jwksURL,
		ExpectedIssuer:   expectedIss,
		ExpectedAudience: expectedAud,
	}

	fmt.Println("starting server at http://localhost:" + port)
	return http.ListenAndServe(":"+port, h)
}

func env(key, fallback string) string {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}

	return v
}
