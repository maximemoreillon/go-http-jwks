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

		keyset, err := ar.Fetch(ctx, certsUrl)
		if err != nil {
			log.Panic("Error loading Fetching JWKS")
		}

		var hasVerified = false

		// TODO: Just use the appropriate key
		for it := keyset.Iterate(context.Background()); it.Next(context.Background()); {
			pair := it.Pair()
			key := pair.Value.(jwk.Key)
		
			var rawkey interface{} // This is the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
			if err := key.Raw(&rawkey); err != nil {
				log.Printf("failed to create public key: %s", err)
				break
			}

			_, err := jws.Verify([]byte(jwt), jwa.RS256, rawkey)

			if err != nil {
				
			} else {
				hasVerified = true
			}
		}

		if(hasVerified) {
			next.ServeHTTP(w, r)
		} else {
			fmt.Fprintf(w, "Invalid token")
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