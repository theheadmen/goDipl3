package main

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"github.com/theheadmen/goDipl3/server/dbconnector"
	"github.com/theheadmen/goDipl3/server/serverapi"
)

func main() {
	// Open the database.
	db, err := sql.Open("sqlite3", "./gophkeeper.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Initialize the database.
	dbconnector.InitDB(db)

	server := serverapi.NewServer(db)

	r := mux.NewRouter()
	r.HandleFunc("/register", server.RegisterHandler)
	r.HandleFunc("/login", server.LoginHandler)
	r.HandleFunc("/store", server.StoreHandler)
	r.HandleFunc("/retrieve", server.RetrieveHandler)

	log.Println("Server is started")

	http.ListenAndServe(":8080", r)
}
