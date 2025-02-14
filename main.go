package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello world")
}

func main () {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	ctx, _ := context.WithCancel(context.Background())

	certsUrl := os.Getenv("JWKS_URI")
	jwt := os.Getenv("JWT")


	ar := jwk.NewAutoRefresh(ctx)
	ar.Configure(certsUrl, jwk.WithMinRefreshInterval(15*time.Minute))

	keyset, err := ar.Fetch(ctx, certsUrl)

	for it := keyset.Iterate(context.Background()); it.Next(context.Background()); {
		pair := it.Pair()
		key := pair.Value.(jwk.Key)
	
		var rawkey interface{} // This is the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
		if err := key.Raw(&rawkey); err != nil {
		  log.Printf("failed to create public key: %s", err)
		  return
		}

		verified, err := jws.Verify([]byte(jwt), jwa.RS256, rawkey)

		if err != nil {
			log.Printf("failed to verify message: %s", err)
		  } else {
			log.Printf("signed message verified! -> %s", verified)

		}

	
	  }


	


	http.HandleFunc("/", handler)
	// fmt.Println("Server started at http://localhost:8080")
	// log.Fatal(http.ListenAndServe(":8081", nil))

}