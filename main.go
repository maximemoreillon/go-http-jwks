package main

import (
	"fmt"
	"log"
	"net/http"

	"jwksExperiments/auth"

	"github.com/joho/godotenv"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello world")
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	mux := http.NewServeMux()
	finalHandler := http.HandlerFunc(handler)
	mux.Handle("/", auth.Middleware(finalHandler))

	fmt.Println("Server started")
	log.Fatal(http.ListenAndServe(":8081", mux))
}
