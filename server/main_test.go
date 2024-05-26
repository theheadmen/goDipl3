package main

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/theheadmen/goDipl3/models"
	"github.com/theheadmen/goDipl3/server/dbconnector"
	"github.com/theheadmen/goDipl3/server/serverapi"
)

func loadServerCertificate() tls.Certificate {
	// Load your server certificate and key here
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatalf("Failed to load server certificate and key: %v", err)
	}
	return cert
}

func TestRegisterHandler(t *testing.T) {
	// Initialize the database and server
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()
	dbconnector.InitDB(db)
	server := serverapi.NewServer(db)

	// Create a new HTTP request with a JSON payload
	user := models.User{
		Username: "testuser",
		Password: "testpassword",
	}
	payload, _ := json.Marshal(user)
	req, err := http.NewRequest("POST", "/register", bytes.NewBuffer(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Create a TLS configuration with the server certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{loadServerCertificate()},
	}

	r := mux.NewRouter()
	r.HandleFunc("/register", server.RegisterHandler)

	// Create a new HTTPS test server with the server's handler and TLS configuration
	ts := httptest.NewTLSServer(r)
	ts.TLS = tlsConfig
	defer ts.Close()

	// Modify the request URL to point to the test server
	req.URL, err = url.Parse(ts.URL + "/register")
	if err != nil {
		t.Fatal(err)
	}

	// Create a client that skips certificate verification for testing purposes
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // This is not secure and should not be used in production
			},
		},
	}

	// Send the request to the test server
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Check the status code of the response
	if status := resp.StatusCode; status != http.StatusCreated {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusCreated)
	}

	// Check that the user was inserted into the database correctly
	var insertedUser models.User
	err = db.QueryRow("SELECT id, username, password FROM users WHERE username = ?", user.Username).Scan(&insertedUser.ID, &insertedUser.Username, &insertedUser.Password)
	if err != nil {
		t.Fatalf("Failed to query inserted user: %v", err)
	}

	// Check that the password was hashed correctly
	hasher := md5.New()
	hasher.Write([]byte(user.Password))
	expectedPassword := hex.EncodeToString(hasher.Sum(nil))
	if insertedUser.Password != expectedPassword {
		t.Errorf("handler stored incorrect password hash: got %v want %v", insertedUser.Password, expectedPassword)
	}
}

func TestLoginHandler(t *testing.T) {
	// Initialize the database and server
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()
	dbconnector.InitDB(db)
	server := serverapi.NewServer(db)

	// Create a test user
	user := models.User{
		Username: "testuser",
		Password: "testpassword",
	}
	hasher := md5.New()
	hasher.Write([]byte(user.Password))
	hashedPassword := hex.EncodeToString(hasher.Sum(nil))
	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", user.Username, hashedPassword)
	if err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}

	// Create a new HTTP request with a JSON payload
	payload, _ := json.Marshal(user)
	req, err := http.NewRequest("POST", "/login", bytes.NewBuffer(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Create a TLS configuration with the server certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{loadServerCertificate()},
	}

	r := mux.NewRouter()
	r.HandleFunc("/login", server.LoginHandler)

	// Create a new HTTPS test server with the server's handler and TLS configuration
	ts := httptest.NewTLSServer(r)
	ts.TLS = tlsConfig
	defer ts.Close()

	// Modify the request URL to point to the test server
	req.URL, err = url.Parse(ts.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}

	// Create a client that skips certificate verification for testing purposes
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // This is not secure and should not be used in production
			},
		},
	}

	// Send the request to the test server
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Check the status code of the response
	if status := resp.StatusCode; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check that the JWT token is set correctly
	cookies := resp.Cookies()
	var tokenCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "token" {
			tokenCookie = cookie
			break
		}
	}
	if tokenCookie == nil {
		t.Error("JWT token cookie not set")
	}
}

func TestStoreHandler(t *testing.T) {
	// Initialize the database and server
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()
	dbconnector.InitDB(db)
	server := serverapi.NewServer(db)

	// Create a test user
	user := models.User{
		Username: "testuser",
		Password: "testpassword",
	}
	hasher := md5.New()
	hasher.Write([]byte(user.Password))
	hashedPassword := hex.EncodeToString(hasher.Sum(nil))
	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", user.Username, hashedPassword)
	if err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}

	// Test cases for different data types
	testCases := []struct {
		name     string
		dataType string
		data     map[string]interface{}
	}{
		{
			name:     "Store text data",
			dataType: "text",
			data: map[string]interface{}{
				"data": "Sample text data",
				"meta": "Sample meta",
			},
		},
		{
			name:     "Store binary data",
			dataType: "binary",
			data: map[string]interface{}{
				"data": "U2FtcGxlIGJpbmFyeSBkYXRh", // Base64 encoded "Sample binary data"
				"meta": "Sample meta",
			},
		},
		{
			name:     "Store bank card data",
			dataType: "bankcard",
			data: map[string]interface{}{
				"number": "1234567812345678",
				"expiry": "12/24",
				"cvv":    "123",
				"meta":   "Sample meta",
			},
		},
	}

	// Set the JWT token in the request header
	expirationTime := time.Now().Add(1 * time.Hour)
	claims := &serverapi.Claims{
		UserID: user.ID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(serverapi.JwtKey)
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	}

	// Create a TLS configuration with the server certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{loadServerCertificate()},
	}

	r := mux.NewRouter()
	r.HandleFunc("/store", server.StoreHandler)
	r.HandleFunc("/retrieve", server.RetrieveHandler)

	// Create a new HTTPS test server with the server's handler and TLS configuration
	ts := httptest.NewTLSServer(r)
	ts.TLS = tlsConfig
	defer ts.Close()

	// Create a client that skips certificate verification for testing purposes
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // This is not secure and should not be used in production
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new HTTP request with a JSON payload
			payload, _ := json.Marshal(tc.data)
			req, err := http.NewRequest("POST", "/store?type="+tc.dataType, bytes.NewBuffer(payload))
			if err != nil {
				t.Fatal(err)
			}

			req.AddCookie(cookie)

			// Modify the request URL to point to the test server
			req.URL, err = url.Parse(ts.URL + "/store?type=" + tc.dataType)
			if err != nil {
				t.Fatal(err)
			}

			// Send the request to the test server
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			// Check the status code of the response
			if status := resp.StatusCode; status != http.StatusCreated {
				t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusCreated)
			}

			respBody, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			respBodyStr := string(respBody)

			// Check the response body
			expectedResponse := "Data stored successfully"
			if respBodyStr != expectedResponse {
				t.Errorf("handler returned unexpected body: got %v want %v", respBodyStr, expectedResponse)
			}

			// Retrieve the data
			retrieveReq, err := http.NewRequest("GET", "/retrieve?type="+tc.dataType, nil)
			if err != nil {
				t.Fatal(err)
			}
			retrieveReq.AddCookie(cookie)
			// Modify the request URL to point to the test server
			retrieveReq.URL, err = url.Parse(ts.URL + "/retrieve?type=" + tc.dataType)
			if err != nil {
				t.Fatal(err)
			}

			// Send the request to the test server
			retrieveResp, err := client.Do(retrieveReq)
			if err != nil {
				t.Fatal(err)
			}
			defer retrieveResp.Body.Close()

			// Check the retrieve response status code
			if retrieveStatus := retrieveResp.StatusCode; retrieveStatus != http.StatusOK {
				t.Errorf("retrieve handler returned wrong status code: got %v want %v", retrieveStatus, http.StatusOK)
			}

			// Check the response body for the retrieved data
			var retrievedData []map[string]interface{}
			err = json.NewDecoder(retrieveResp.Body).Decode(&retrievedData)
			if err != nil {
				t.Errorf("failed to decode retrieve response body: %v", err)
			}

			// Assuming the retrieved data is a list, check the length and compare individual items
			if len(retrievedData) != 1 {
				t.Errorf("expected 1 item retrieved, got %d", len(retrievedData))
			} else {
				if tc.dataType == "binary" {
					// Compare the retrieved data with the stored data
					expectedData := []byte(tc.data["data"].(string))

					retrievedBase64Data := retrievedData[0]["data"].(string)
					retrievedBinaryData, err := base64.StdEncoding.DecodeString(retrievedBase64Data)
					if err != nil {
						t.Errorf("failed to decode retrieved data: %v", err)
					}

					// Compare the decoded binary data
					if !bytes.Equal(expectedData, retrievedBinaryData) {
						t.Errorf("retrieved binary data does not match stored binary data: got %v want %v", retrievedBinaryData, expectedData)
					}

					// Compare the meta data
					if retrievedData[0]["meta"] != tc.data["meta"] {
						t.Errorf("retrieved meta does not match stored meta: got %v want %v", retrievedData[0]["meta"], tc.data["meta"])
					}
				} else {
					// Compare the retrieved data with the stored data
					for key, value := range tc.data {
						if retrievedData[0][key] != value {
							t.Errorf("retrieved data does not match stored data for key %s: got %v want %v", key, retrievedData[0][key], value)
						}
					}
				}
			}
		})
	}
}
