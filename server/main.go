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
	r.HandleFunc("/sync", server.SyncHandler)
	r.HandleFunc("/retrieve", server.RetrieveHandler)
	r.HandleFunc("/delete", server.DeleteHandler)
	r.HandleFunc("/update", server.UpdateHandler)

	r.HandleFunc("/store_file", server.StoreFileHandler)
	r.HandleFunc("/get_file", server.GetFileHandler)
	r.HandleFunc("/get_list_files", server.ListFilesHandler)
	r.HandleFunc("/delete_file", server.DeleteFileHandler)

	log.Println("Server is started")

	serverReal := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	if err := serverReal.ListenAndServeTLS("cert.pem", "key.pem"); err != nil && err != http.ErrServerClosed {
		log.Println("Server is down")
	}
}
