package serverapi

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/theheadmen/goDipl3/models"
	"github.com/theheadmen/goDipl3/server/dbconnector"
)

// Server is a struct that holds the database connection.
type Server struct {
	db *sql.DB
}

// NewServer creates a new Server instance with the given database connection.
func NewServer(db *sql.DB) *Server {
	return &Server{db: db}
}

// JWT secret key, this should be stored securely and not exposed in the code.
var JwtKey = []byte("my_secret_key")

// Claims is a struct that will be encoded to a JWT.
type Claims struct {
	UserID int `json:"user_id"`
	jwt.StandardClaims
}

// RegisterHandler handles the registration of new users.
func (s *Server) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Register query")
	// Parse the request body.
	var user models.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Println(user)

	// Check if the user already exists.
	err = dbconnector.CheckUserExists(user, s.db)
	if err != sql.ErrNoRows {
		log.Println("User already exists")
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	// Hash the password.
	hasher := md5.New()
	hasher.Write([]byte(user.Password))
	user.Password = hex.EncodeToString(hasher.Sum(nil))

	// Insert the user into the database.
	result, err := dbconnector.InsertNewUser(user, s.db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get the ID of the newly inserted user.
	userID, err := result.LastInsertId()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	user.ID = int(userID)

	// Create a new JWT token.
	expirationTime := time.Now().Add(1 * time.Hour)
	claims := &Claims{
		UserID: user.ID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(JwtKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set the JWT token as a cookie.
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

	// Return the user ID.
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "User registered with ID: %d", user.ID)
}

// LoginHandler handles the login of existing users.
func (s *Server) LoginHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Login query")
	// Parse the request body.
	var user models.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Println(user)

	// Hash the password.
	hasher := md5.New()
	hasher.Write([]byte(user.Password))
	hashedPassword := hex.EncodeToString(hasher.Sum(nil))

	// Retrieve the user from the database.
	storedUser, err := dbconnector.GetUserByName(user.Username, s.db)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Check if the password matches.
	if storedUser.Password != hashedPassword {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Create a new JWT token.
	expirationTime := time.Now().Add(1 * time.Hour)
	log.Println("Login for", storedUser)
	claims := &Claims{
		UserID: storedUser.ID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(JwtKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set the JWT token as a cookie.
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

	// Return the user ID.
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User logged in with ID: %d", storedUser.ID)
}

// StoreHandler handles the storage of user data.
func (s *Server) StoreHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Store query")
	// Parse the request body.
	var data map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		log.Println("can't decode body for store")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get the data type.
	dataType := r.URL.Query().Get("type")

	// Get the user ID from the JWT token.
	userID, err := getUserIDFromToken(r)
	if err != nil {
		log.Println("getUserIDFromToken error: ", err.Error())
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	log.Println("store", dataType, "for", userID)

	// Store the data based on the type.
	switch dataType {
	case "text":
		err = dbconnector.StoreTextData(userID, data, s.db)
	case "binary":
		err = dbconnector.StoreBinaryData(userID, data, s.db)
	case "bankcard":
		err = dbconnector.StoreBankCard(userID, data, s.db)
	default:
		log.Println("invalid data type: ", dataType)
		http.Error(w, "Invalid data type", http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Data stored successfully")
}

// getUserIDFromToken retrieves the user ID from the JWT token in the request.
func getUserIDFromToken(r *http.Request) (int, error) {
	c, err := r.Cookie("token")
	if err != nil {
		return 0, err
	}

	tokenString := c.Value
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return JwtKey, nil
	})
	log.Println("got claims from cookie", claims, claims.UserID)

	if err != nil || !token.Valid {
		return 0, err
	}

	return claims.UserID, nil
}

// RetrieveHandler handles the retrieval of user data.
func (s *Server) RetrieveHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Retrieve query")
	// Get the user ID from the JWT token.
	userID, err := getUserIDFromToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Retrieve the data based on the type.
	dataType := r.URL.Query().Get("type")
	log.Println("for ", dataType)
	switch dataType {
	case "text":
		textData, err := dbconnector.RetrieveTextData(userID, s.db)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(textData)
	case "binary":
		binaryData, err := dbconnector.RetrieveBinaryData(userID, s.db)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(binaryData)
	case "bankcard":
		bankCards, err := dbconnector.RetrieveBankCards(userID, s.db)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(bankCards)
	default:
		http.Error(w, "Invalid data type", http.StatusBadRequest)
		return
	}
}
