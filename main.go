package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/lestrrat-go/iter/arrayiter"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
)


func middleware(next http.Handler) http.Handler {

	ctx, _ := context.WithCancel(context.Background())

	certsUrl := os.Getenv("JWKS_URI")


	ar := jwk.NewAutoRefresh(ctx)
	ar.Configure(certsUrl, jwk.WithMinRefreshInterval(15*time.Minute))

	

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		authHeader := r.Header.Get("Authorization")

		jwt := strings.Split(authHeader, "Bearer ")[1]
		// TODO: handle case where no JWT is provided

		keyset, err := ar.Fetch(ctx, certsUrl)
		if err != nil {
			log.Panic("Error loading Fetching JWKS")
		}

		// Finding key pair with RS256 algorithm
		var pair *arrayiter.Pair
		for it := keyset.Iterate(context.Background()); it.Next(context.Background()); {
			alg := it.Pair().Value.(jwk.Key).Algorithm()
			if alg == "RS256" {
				pair = it.Pair()
				break
			}
		}

		var rawkey interface{}
		key := pair.Value.(jwk.Key)
		if err := key.Raw(&rawkey); err != nil {
			fmt.Fprintf(w,"failed to create public key: %s", err)
			return
		}

		_, verifyErr := jws.Verify([]byte(jwt), jwa.RS256, rawkey)

		if verifyErr != nil {
			fmt.Fprintf(w, "Invalid token")
		} else {
			next.ServeHTTP(w, r)
		}



	})

}


func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello world")
}

func main () {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	


	mux := http.NewServeMux()

	finalHandler := http.HandlerFunc(handler)
	mux.Handle("/", middleware(finalHandler))


	fmt.Println("Server started")
	log.Fatal(http.ListenAndServe(":8081", mux))

}