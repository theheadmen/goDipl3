package serverapi

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/theheadmen/goDipl3/models"
	"github.com/theheadmen/goDipl3/server/dbconnector"
	"github.com/theheadmen/goDipl3/utils"
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
		textData, cerr := utils.CreateTextData(userID, data)
		if cerr != nil {
			http.Error(w, cerr.Error(), http.StatusBadRequest)
			return
		}
		err = dbconnector.StoreTextData(textData, s.db)
	case "binary":
		binaryData, cerr := utils.CreateBinaryData(userID, data)
		if cerr != nil {
			http.Error(w, cerr.Error(), http.StatusBadRequest)
			return
		}
		err = dbconnector.StoreBinaryData(binaryData, s.db)
	case "bankcard":
		bankCard, cerr := utils.CreateBankCard(userID, data)
		if cerr != nil {
			http.Error(w, cerr.Error(), http.StatusBadRequest)
			return
		}
		err = dbconnector.StoreBankCard(bankCard, s.db)
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

// SyncHandler handles save and update of user data.
func (s *Server) SyncHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Sync query")
	// Get the data type.
	dataType := r.URL.Query().Get("type")

	// Get the user ID from the JWT token.
	userID, err := getUserIDFromToken(r)
	if err != nil {
		log.Println("getUserIDFromToken error: ", err.Error())
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	log.Println("sync", dataType, "for", userID)

	// Convert the data array to the appropriate type.
	switch dataType {
	case "text":
		var textDataArray []models.TextData
		err = json.NewDecoder(r.Body).Decode(&textDataArray)
		if err != nil {
			log.Println("can't decode body for store multiple")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		err = dbconnector.SaveAndUpdateTextData(textDataArray, s.db)
	case "binary":
		var binaryDataArray []models.BinaryData
		err = json.NewDecoder(r.Body).Decode(&binaryDataArray)
		if err != nil {
			log.Println("can't decode body for store multiple")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		err = dbconnector.SaveAndUpdateBinaryData(binaryDataArray, s.db)
	case "bankcard":
		var bankCardArray []models.BankCard
		err = json.NewDecoder(r.Body).Decode(&bankCardArray)
		if err != nil {
			log.Println("can't decode body for store multiple")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		err = dbconnector.SaveAndUpdateBankData(bankCardArray, s.db)
	default:
		log.Println("invalid data type: ", dataType)
		http.Error(w, "Invalid data type", http.StatusBadRequest)
		return
	}

	if err != nil {
		log.Println("sync error: ", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Data synced successfully")
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

// DeleteHandler handles the deletion of user data.
func (s *Server) DeleteHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Delete query")

	// Get the data type.
	dataType := r.URL.Query().Get("type")

	// Get the user ID from the JWT token.
	userID, err := getUserIDFromToken(r)
	if err != nil {
		log.Println("getUserIDFromToken error: ", err.Error())
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Get the data ID from the URL.
	dataID := r.URL.Query().Get("id")

	log.Println("delete", dataType, "for", userID)

	// Delete the data based on the type.
	switch dataType {
	case "text":
		err = dbconnector.DeleteTextData(userID, dataID, s.db)
	case "binary":
		err = dbconnector.DeleteBinaryData(userID, dataID, s.db)
	case "bankcard":
		err = dbconnector.DeleteBankCard(userID, dataID, s.db)
	default:
		log.Println("invalid data type: ", dataType)
		http.Error(w, "Invalid data type", http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Data deleted successfully")
}

// UpdateHandler handles the update of user data.
func (s *Server) UpdateHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Update query")
	// Parse the request body.
	var data map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		log.Println("can't decode body for update")
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

	// Get the data ID from the URL.
	dataID := r.URL.Query().Get("data_id")

	log.Println("update", dataType, "for", userID)

	// Update the data based on the type.
	switch dataType {
	case "text":
		err = dbconnector.UpdateTextData(userID, dataID, data, s.db)
	case "binary":
		err = dbconnector.UpdateBinaryData(userID, dataID, data, s.db)
	case "bankcard":
		err = dbconnector.UpdateBankCard(userID, dataID, data, s.db)
	default:
		log.Println("invalid data type: ", dataType)
		http.Error(w, "Invalid data type", http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Data updated successfully")
}

// StoreFileHandler handles the storage of user files.
func (s *Server) StoreFileHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Store file query")

	// Get the user ID from the JWT token.
	userID, err := getUserIDFromToken(r)
	if err != nil {
		log.Println("getUserIDFromToken error: ", err.Error())
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Parse the multipart form.
	err = r.ParseMultipartForm(32 << 20) // limit your max input length!
	if err != nil {
		log.Println("can't parse multipart form: ", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get the file from the form.
	file, handler, err := r.FormFile("file")
	if err != nil {
		log.Println("can't get file from form: ", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Save the file to the server.
	fileName, err := saveFileToServer(file, handler.Filename, userID)
	if err != nil {
		log.Println("can't save file to server: ", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Store the file information in the database.
	err = dbconnector.StoreFileData(userID, "files/"+fileName, fileName, s.db)
	if err != nil {
		log.Println("can't store file data: ", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "File stored successfully")
}

// saveFileToServer saves the file to the server.
func saveFileToServer(file multipart.File, fileName string, userID int) (string, error) {
	// Add the user ID to the file name.
	fileNameParts := strings.Split(fileName, ".")
	fileNameParts[0] = fmt.Sprintf("%s_%d", fileNameParts[0], userID)
	fileName = strings.Join(fileNameParts, ".")

	// Create the file on the server.
	f, err := os.OpenFile("./files/"+fileName, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// Copy the file to the server.
	_, err = io.Copy(f, file)
	if err != nil {
		return "", err
	}

	return fileName, nil
}

// GetFileHandler handles the retrieval of user files.
func (s *Server) GetFileHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Get file query")

	// Get the user ID from the JWT token.
	userID, err := getUserIDFromToken(r)
	if err != nil {
		log.Println("getUserIDFromToken error: ", err.Error())
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Get the file name from the query parameters.
	fileName := r.URL.Query().Get("fileName")
	if fileName == "" {
		log.Println("fileName is not provided")
		http.Error(w, "fileName is not provided", http.StatusBadRequest)
		return
	}

	log.Println("we try to get", fileName, "for", userID)

	// Get the file path from the database.
	filePath, err := dbconnector.GetFilePath(userID, fileName, s.db)
	if err != nil {
		log.Println("can't get file path: ", err.Error(), fileName)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Open the file.
	file, err := os.Open("./" + filePath)
	if err != nil {
		log.Println("can't open file: ", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Set the appropriate headers.
	w.Header().Set("Content-Disposition", "attachment; filename="+fileName)
	w.Header().Set("Content-Type", r.Header.Get("Content-Type"))

	// Stream the file to the client.
	_, err = io.Copy(w, file)
	if err != nil {
		log.Println("can't stream file: ", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// ListFilesHandler handles the retrieval of all file names for a user.
func (s *Server) ListFilesHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("List files query")

	// Get the user ID from the JWT token.
	userID, err := getUserIDFromToken(r)
	if err != nil {
		log.Println("getUserIDFromToken error: ", err.Error())
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Get the list of file names from the database.
	fileNames, err := dbconnector.GetFileNames(userID, s.db)
	if err != nil {
		log.Println("can't get file names: ", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert the list of file names to JSON.
	fileNamesJSON, err := json.Marshal(fileNames)
	if err != nil {
		log.Println("can't marshal file names: ", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Write the JSON to the response.
	w.Header().Set("Content-Type", "application/json")
	w.Write(fileNamesJSON)
}

// DeleteFileHandler handles the deletion of user files.
func (s *Server) DeleteFileHandler(w http.ResponseWriter, r *http.Request) {
	// Get the user ID from the JWT token.
	userID, err := getUserIDFromToken(r)
	if err != nil {
		log.Println("getUserIDFromToken error: ", err.Error())
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Get the file name from the query parameters.
	fileName := r.URL.Query().Get("fileName")
	if fileName == "" {
		log.Println("fileName is not provided")
		http.Error(w, "fileName is not provided", http.StatusBadRequest)
		return
	}

	// Get the file path from the database.
	filePath, err := dbconnector.GetFilePath(userID, fileName, s.db)
	if err != nil {
		log.Println("can't get file path: ", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Check if the file exists on the server.
	if _, err := os.Stat("./" + filePath); os.IsNotExist(err) {
		log.Println("file does not exist on the server")
		http.Error(w, "file does not exist on the server", http.StatusNotFound)
		return
	}

	// Delete the file from the server.
	err = os.Remove("./" + filePath)
	if err != nil {
		log.Println("can't delete file: ", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Delete the file information from the database.
	err = dbconnector.DeleteFileData(userID, fileName, s.db)
	if err != nil {
		log.Println("can't delete file data: ", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "File deleted successfully")
}
