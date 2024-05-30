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
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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

func TestDeleteHandler(t *testing.T) {
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

	textData := models.TextData{
		UserID:    user.ID,
		Data:      "data",
		Meta:      "meta",
		CreatedAt: time.Now(),
	}
	_, err = db.Exec("INSERT INTO text_data (user_id, data, meta, created_at) VALUES (?, ?, ?, ?)", textData.UserID, textData.Data, textData.Meta, textData.CreatedAt)
	if err != nil {
		t.Fatalf("Failed to insert test textdata: %v", err)
	}

	binaryData := models.BinaryData{
		UserID:    user.ID,
		Data:      []byte("123456789"),
		Meta:      "meta",
		CreatedAt: time.Now(),
	}

	_, err = db.Exec("INSERT INTO binary_data (user_id, data, meta, created_at) VALUES (?, ?, ?, ?)", binaryData.UserID, binaryData.Data, binaryData.Meta, binaryData.CreatedAt)
	if err != nil {
		t.Fatalf("Failed to insert test binarydata: %v", err)
	}

	bankCard := models.BankCard{
		UserID:    user.ID,
		Number:    "123456",
		Expiry:    "12/24",
		CVV:       "888",
		Meta:      "meta",
		CreatedAt: time.Now(),
	}

	_, err = db.Exec("INSERT INTO bank_cards (user_id, number, expiry, cvv, meta, created_at) VALUES (?, ?, ?, ?, ?, ?)", bankCard.UserID, bankCard.Number, bankCard.Expiry, bankCard.CVV, bankCard.Meta, bankCard.CreatedAt)
	if err != nil {
		t.Fatalf("Failed to insert test bankdata: %v", err)
	}

	// Test cases for different data types
	testCases := []struct {
		name     string
		dataType string
		dataID   string
		code     int
	}{
		{
			name:     "Delete text data",
			dataType: "text",
			dataID:   "1",
			code:     http.StatusOK,
		},
		{
			name:     "Delete text data with error",
			dataType: "text",
			dataID:   "1",
			code:     http.StatusInternalServerError,
		},
		{
			name:     "Delete binary data",
			dataType: "binary",
			dataID:   "1",
			code:     http.StatusOK,
		},
		{
			name:     "Delete bank card data",
			dataType: "bankcard",
			dataID:   "1",
			code:     http.StatusOK,
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
	r.HandleFunc("/delete", server.DeleteHandler)

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
			// Create a new HTTP request
			req, err := http.NewRequest("POST", "/delete?type="+tc.dataType+"&id="+tc.dataID, nil)
			if err != nil {
				t.Fatal(err)
			}

			req.AddCookie(cookie)

			// Modify the request URL to point to the test server
			req.URL, err = url.Parse(ts.URL + "/delete?type=" + tc.dataType + "&id=" + tc.dataID)
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
			if status := resp.StatusCode; status != tc.code {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tc.code)
			}
		})
	}
}

func TestUpdateHandler(t *testing.T) {
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
		dataUpd  map[string]interface{}
	}{
		{
			name:     "Update text data",
			dataType: "text",
			data: map[string]interface{}{
				"data": "Sample text data",
				"meta": "Sample meta",
			},
			dataUpd: map[string]interface{}{
				"data": "Upd text data",
				"meta": "Upd meta",
			},
		},
		{
			name:     "Update binary data",
			dataType: "binary",
			data: map[string]interface{}{
				"data": "U2FtcGxlIGJpbmFyeSBkYXRh", // Base64 encoded "Sample binary data"
				"meta": "Sample meta",
			},
			dataUpd: map[string]interface{}{
				"data": "U2FtcGxlIGJpbmFyeSB12345",
				"meta": "Upd meta",
			},
		},
		{
			name:     "Update bank card data",
			dataType: "bankcard",
			data: map[string]interface{}{
				"number": "1234567812345678",
				"expiry": "12/24",
				"cvv":    "123",
				"meta":   "Sample meta",
			},
			dataUpd: map[string]interface{}{
				"number": "234234234234344",
				"expiry": "11/26",
				"cvv":    "321",
				"meta":   "Upd meta",
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
	r.HandleFunc("/update", server.UpdateHandler)

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

			// Create a new HTTP update request with a JSON payload
			payload, _ = json.Marshal(tc.dataUpd)
			req, err = http.NewRequest("POST", "/update?type="+tc.dataType+"&data_id=1", bytes.NewBuffer(payload))
			if err != nil {
				t.Fatal(err)
			}

			req.AddCookie(cookie)

			// Modify the request URL to point to the test server
			req.URL, err = url.Parse(ts.URL + "/update?type=" + tc.dataType + "&data_id=1")
			if err != nil {
				t.Fatal(err)
			}

			// Send the request to the test server
			resp, err = client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			// Check the status code of the response
			if status := resp.StatusCode; status != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
			}

			respBody, err = io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			respBodyStr = string(respBody)

			// Check the response body
			expectedResponse = "Data updated successfully"
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
					expectedData := []byte(tc.dataUpd["data"].(string))

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
						t.Errorf("retrieved meta does not match stored meta: got %v want %v", retrievedData[0]["meta"], tc.dataUpd["meta"])
					}
				} else {
					// Compare the retrieved data with the stored data
					for key, value := range tc.dataUpd {
						if retrievedData[0][key] != value {
							t.Errorf("retrieved data does not match stored data for key %s: got %v want %v", key, retrievedData[0][key], value)
						}
					}
				}
			}
		})
	}
}

// TestFileHandlers tests the file storage, listing, and retrieval handlers.
func TestFileHandlers(t *testing.T) {
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
	r.HandleFunc("/store_file", server.StoreFileHandler)
	r.HandleFunc("/get_file", server.GetFileHandler)
	r.HandleFunc("/get_list_files", server.ListFilesHandler)
	r.HandleFunc("/delete_file", server.DeleteFileHandler)

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

	// Create a test file to upload.
	filePath := "./testfile.txt"
	file, err := os.Open(filePath)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer file.Close()

	// Create a multipart writer to create the form data.
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("file", filepath.Base(file.Name()))
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}
	_, err = io.Copy(part, file)
	if err != nil {
		t.Fatalf("Failed to copy file to form: %v", err)
	}
	err = writer.Close()
	if err != nil {
		t.Fatalf("Failed to close writer: %v", err)
	}

	// Make a request to store the file.
	req, err := http.NewRequest("POST", "/store_file", &buf)
	if err != nil {
		t.Fatal(err)
	}

	req.AddCookie(cookie)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Modify the request URL to point to the test server
	req.URL, err = url.Parse(ts.URL + "/store_file")
	if err != nil {
		t.Fatal(err)
	}

	// Send the request to the test server
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	if res.StatusCode != http.StatusCreated {
		t.Errorf("Expected status code %v, got %v", http.StatusCreated, res.StatusCode)
	}

	// Make a request to list the files.
	req, err = http.NewRequest("GET", "/get_list_files", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.AddCookie(cookie)

	// Modify the request URL to point to the test server
	req.URL, err = url.Parse(ts.URL + "/get_list_files")
	if err != nil {
		t.Fatal(err)
	}
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %v, got %v", http.StatusOK, res.StatusCode)
	}

	// Parse the response to get the list of file names.
	var fileNames []string
	err = json.NewDecoder(res.Body).Decode(&fileNames)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if len(fileNames) == 0 {
		t.Fatalf("No files found")
	}

	// Make a request to get the first file.
	req, err = http.NewRequest("GET", "/get_file?fileName="+fileNames[0], nil)
	if err != nil {
		t.Fatal(err)
	}

	req.AddCookie(cookie)

	// Modify the request URL to point to the test server
	req.URL, err = url.Parse(ts.URL + "/get_file?fileName=" + fileNames[0])
	if err != nil {
		t.Fatal(err)
	}

	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %v, got %v", http.StatusOK, res.StatusCode)
	}

	// Read the response body to get the file content.
	fileContent, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	// Compare the file content with the original file.
	originalFileContent, err := ioutil.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read original file: %v", err)
	}
	if !bytes.Equal(fileContent, originalFileContent) {
		t.Errorf("File content does not match")
	}

	// Make a request to delete the first file.
	req, err = http.NewRequest("GET", "/delete_file?fileName="+fileNames[0], nil)
	if err != nil {
		t.Fatal(err)
	}

	req.AddCookie(cookie)

	// Modify the request URL to point to the test server
	req.URL, err = url.Parse(ts.URL + "/delete_file?fileName=" + fileNames[0])
	if err != nil {
		t.Fatal(err)
	}

	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %v, got %v", http.StatusOK, res.StatusCode)
	}

	// Check if the file was deleted.
	if _, err := os.Stat("./" + fileNames[0]); !os.IsNotExist(err) {
		t.Errorf("Expected file to be deleted, but it still exists")
	}
}
