package main

import (
	"bytes"
	"crypto/md5"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/theheadmen/goDipl3/models"
	"github.com/theheadmen/goDipl3/server/dbconnector"
	"github.com/theheadmen/goDipl3/server/serverapi"
)

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

	// Create a ResponseRecorder to record the response
	rr := httptest.NewRecorder()

	// Call the handler function, passing in the ResponseRecorder and the HTTP request
	handler := http.HandlerFunc(server.RegisterHandler)
	handler.ServeHTTP(rr, req)

	// Check the status code of the response
	if status := rr.Code; status != http.StatusCreated {
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

	// Create a ResponseRecorder to record the response
	rr := httptest.NewRecorder()

	// Call the handler function, passing in the ResponseRecorder and the HTTP request
	handler := http.HandlerFunc(server.LoginHandler)
	handler.ServeHTTP(rr, req)

	// Check the status code of the response
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check that the JWT token is set correctly
	cookies := rr.Result().Cookies()
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

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new HTTP request with a JSON payload
			payload, _ := json.Marshal(tc.data)
			req, err := http.NewRequest("POST", "/store?type="+tc.dataType, bytes.NewBuffer(payload))
			if err != nil {
				t.Fatal(err)
			}

			req.AddCookie(cookie)

			// Create a ResponseRecorder to record the response
			rr := httptest.NewRecorder()

			// Call the handler function, passing in the ResponseRecorder and the HTTP request
			handler := http.HandlerFunc(server.StoreHandler)
			handler.ServeHTTP(rr, req)

			// Check the status code of the response
			if status := rr.Code; status != http.StatusCreated {
				t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusCreated)
			}

			// Check the response body
			expectedResponse := "Data stored successfully"
			if rr.Body.String() != expectedResponse {
				t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expectedResponse)
			}

			// Retrieve the data
			retrieveReq, err := http.NewRequest("GET", "/retrieve?type="+tc.dataType, nil)
			if err != nil {
				t.Fatal(err)
			}
			retrieveReq.AddCookie(cookie)
			retrieveRR := httptest.NewRecorder()
			rethandler := http.HandlerFunc(server.RetrieveHandler)
			rethandler.ServeHTTP(retrieveRR, retrieveReq)

			// Check the retrieve response status code
			if retrieveStatus := retrieveRR.Code; retrieveStatus != http.StatusOK {
				t.Errorf("retrieve handler returned wrong status code: got %v want %v", retrieveStatus, http.StatusOK)
			}

			// Check the response body for the retrieved data
			var retrievedData []map[string]interface{}
			err = json.NewDecoder(retrieveRR.Body).Decode(&retrievedData)
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
