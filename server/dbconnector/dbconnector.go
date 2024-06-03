package dbconnector

import (
	"database/sql"
	"errors"
	"log"
	"time"

	"github.com/theheadmen/goDipl3/models"
)

// InitDB initializes the SQLite database and creates tables for the data structures.
func InitDB(db *sql.DB) {
	// Create the User table.
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		log.Fatalf("Failed to create users table: %v", err)
	}

	// Create the TextData table.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS text_data (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			data TEXT NOT NULL,
			meta TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(user_id) REFERENCES users(id)
		)
	`)
	if err != nil {
		log.Fatalf("Failed to create text_data table: %v", err)
	}

	// Create the BinaryData table.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS binary_data (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			data BLOB NOT NULL,
			meta TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(user_id) REFERENCES users(id)
		)
	`)
	if err != nil {
		log.Fatalf("Failed to create binary_data table: %v", err)
	}

	// Create the BankCard table.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS bank_cards (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			number TEXT NOT NULL,
			expiry TEXT NOT NULL,
			cvv TEXT NOT NULL,
			meta TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(user_id) REFERENCES users(id)
		)
	`)
	if err != nil {
		log.Fatalf("Failed to create bank_cards table: %v", err)
	}

	// Create the FileData table.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS file_data (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			file_path TEXT NOT NULL,
			file_name TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(user_id) REFERENCES users(id)
		)
	`)
	if err != nil {
		log.Fatalf("Failed to create text_data table: %v", err)
	}

	log.Println("DB init success")
}

func CheckUserExists(user models.User, db *sql.DB) error {
	var existingUserID int
	err := db.QueryRow("SELECT id FROM users WHERE username = ?", user.Username).Scan(&existingUserID)
	return err
}

func InsertNewUser(user models.User, db *sql.DB) (sql.Result, error) {
	result, err := db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", user.Username, user.Password)
	return result, err
}

func GetUserByName(username string, db *sql.DB) (models.User, error) {
	var storedUser models.User
	err := db.QueryRow("SELECT id, username, password FROM users WHERE username = ?", username).Scan(&storedUser.ID, &storedUser.Username, &storedUser.Password)
	return storedUser, err
}

// storeTextData stores text data for the given user.
func StoreTextData(textData models.TextData, db *sql.DB) error {
	log.Println("store text", textData)

	_, err := db.Exec("INSERT INTO text_data (user_id, data, meta, created_at) VALUES (?, ?, ?, ?)", textData.UserID, textData.Data, textData.Meta, textData.CreatedAt)
	return err
}

// storeBinaryData stores binary data for the given user.
func StoreBinaryData(binaryData models.BinaryData, db *sql.DB) error {
	log.Println("store binary", binaryData)

	_, err := db.Exec("INSERT INTO binary_data (user_id, data, meta, created_at) VALUES (?, ?, ?, ?)", binaryData.UserID, binaryData.Data, binaryData.Meta, binaryData.CreatedAt)
	return err
}

// storeBankCard stores bank card data for the given user.
func StoreBankCard(bankCard models.BankCard, db *sql.DB) error {
	log.Println("store bank card", bankCard)

	_, err := db.Exec("INSERT INTO bank_cards (user_id, number, expiry, cvv, meta, created_at) VALUES (?, ?, ?, ?, ?, ?)", bankCard.UserID, bankCard.Number, bankCard.Expiry, bankCard.CVV, bankCard.Meta, bankCard.CreatedAt)
	return err
}

// retrieveTextData retrieves text data for the given user.
func RetrieveTextData(userID int, db *sql.DB) ([]models.TextData, error) {
	rows, err := db.Query("SELECT id, user_id, data, meta, created_at FROM text_data WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var textDataList []models.TextData
	for rows.Next() {
		var textData models.TextData
		err := rows.Scan(&textData.ID, &textData.UserID, &textData.Data, &textData.Meta, &textData.CreatedAt)
		if err != nil {
			return nil, err
		}
		textDataList = append(textDataList, textData)
	}

	return textDataList, nil
}

// retrieveBinaryData retrieves binary data for the given user.
func RetrieveBinaryData(userID int, db *sql.DB) ([]models.BinaryData, error) {
	rows, err := db.Query("SELECT id, user_id, data, meta, created_at FROM binary_data WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var binaryDataList []models.BinaryData
	for rows.Next() {
		var binaryData models.BinaryData
		err := rows.Scan(&binaryData.ID, &binaryData.UserID, &binaryData.Data, &binaryData.Meta, &binaryData.CreatedAt)
		if err != nil {
			return nil, err
		}
		binaryDataList = append(binaryDataList, binaryData)
	}

	return binaryDataList, nil
}

// retrieveBankCards retrieves bank card data for the given user.
func RetrieveBankCards(userID int, db *sql.DB) ([]models.BankCard, error) {
	rows, err := db.Query("SELECT id, user_id, number, expiry, cvv, meta, created_at FROM bank_cards WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bankCardsList []models.BankCard
	for rows.Next() {
		var bankCard models.BankCard
		err := rows.Scan(&bankCard.ID, &bankCard.UserID, &bankCard.Number, &bankCard.Expiry, &bankCard.CVV, &bankCard.Meta, &bankCard.CreatedAt)
		if err != nil {
			return nil, err
		}
		bankCardsList = append(bankCardsList, bankCard)
	}

	return bankCardsList, nil
}

// deleteTextData deletes text data for the given user.
func DeleteTextData(userID int, dataID string, db *sql.DB) error {
	// Check if the data exists
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM text_data WHERE user_id = ? AND id = ?", userID, dataID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("data not found")
	}

	// Delete the data
	_, err = db.Exec("DELETE FROM text_data WHERE user_id = ? AND id = ?", userID, dataID)
	return err
}

// deleteBinaryData deletes binary data for the given user.
func DeleteBinaryData(userID int, dataID string, db *sql.DB) error {
	// Check if the data exists
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM binary_data WHERE user_id = ? AND id = ?", userID, dataID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("data not found")
	}

	// Delete the data
	_, err = db.Exec("DELETE FROM binary_data WHERE user_id = ? AND id = ?", userID, dataID)
	return err
}

// deleteBankCard deletes bank card data for the given user.
func DeleteBankCard(userID int, dataID string, db *sql.DB) error {
	// Check if the data exists
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM bank_cards WHERE user_id = ? AND id = ?", userID, dataID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("data not found")
	}

	// Delete the data
	_, err = db.Exec("DELETE FROM bank_cards WHERE user_id = ? AND id = ?", userID, dataID)
	return err
}

// updateTextData updates text data for the given user.
func UpdateTextData(userID int, dataID string, data map[string]interface{}, db *sql.DB) error {
	// Check if the data exists.
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM text_data WHERE id = ? AND user_id = ?)", dataID, userID).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("data not found")
	}

	textData := models.TextData{
		UserID: userID,
		Data:   data["data"].(string),
		Meta:   data["meta"].(string),
		//UpdatedAt: time.Now(),
	}
	log.Println("update text", textData)

	_, err = db.Exec("UPDATE text_data SET data = ?, meta = ? WHERE id = ? AND user_id = ?", textData.Data, textData.Meta, dataID, userID)
	return err
}

// updateBinaryData updates binary data for the given user.
func UpdateBinaryData(userID int, dataID string, data map[string]interface{}, db *sql.DB) error {
	// Check if the data exists.
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM binary_data WHERE id = ? AND user_id = ?)", dataID, userID).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("data not found")
	}

	binaryData := models.BinaryData{
		UserID: userID,
		Data:   []byte(data["data"].(string)),
		Meta:   data["meta"].(string),
		//UpdatedAt: time.Now(),
	}

	_, err = db.Exec("UPDATE binary_data SET data = ?, meta = ? WHERE id = ? AND user_id = ?", binaryData.Data, binaryData.Meta, dataID, userID)
	return err
}

// updateBankCard updates bank card data for the given user.
func UpdateBankCard(userID int, dataID string, data map[string]interface{}, db *sql.DB) error {
	// Check if the data exists.
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM bank_cards WHERE id = ? AND user_id = ?)", dataID, userID).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("data not found")
	}

	bankCard := models.BankCard{
		UserID: userID,
		Number: data["number"].(string),
		Expiry: data["expiry"].(string),
		CVV:    data["cvv"].(string),
		Meta:   data["meta"].(string),
		//UpdatedAt: time.Now(),
	}

	_, err = db.Exec("UPDATE bank_cards SET number = ?, expiry = ?, cvv = ?, meta = ? WHERE id = ? AND user_id = ?", bankCard.Number, bankCard.Expiry, bankCard.CVV, bankCard.Meta, dataID, userID)
	return err
}

// storeFileData stores file data for the given user.
func StoreFileData(userID int, filePath string, fileName string, db *sql.DB) error {
	fileData := models.FileData{
		UserID:    userID,
		FilePath:  filePath,
		FileName:  fileName,
		CreatedAt: time.Now(),
	}

	_, err := db.Exec("INSERT INTO file_data (user_id, file_path, file_name, created_at) VALUES (?, ?, ?, ?)", fileData.UserID, fileData.FilePath, fileData.FileName, fileData.CreatedAt)
	return err
}

// getFilePath retrieves the file path from the database.
func GetFilePath(userID int, fileName string, db *sql.DB) (string, error) {
	var filePath string
	err := db.QueryRow("SELECT file_path FROM file_data WHERE user_id = ? AND file_name = ?", userID, fileName).Scan(&filePath)
	if err != nil {
		return "", err
	}
	return filePath, nil
}

// getFileNames retrieves the list of file names from the database.
func GetFileNames(userID int, db *sql.DB) ([]string, error) {
	rows, err := db.Query("SELECT file_name FROM file_data WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var fileNames []string
	for rows.Next() {
		var fileName string
		if err := rows.Scan(&fileName); err != nil {
			return nil, err
		}
		fileNames = append(fileNames, fileName)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return fileNames, nil
}

// deleteFileData deletes file data for the given user.
func DeleteFileData(userID int, fileName string, db *sql.DB) error {
	_, err := db.Exec("DELETE FROM file_data WHERE user_id = ? AND file_name = ?", userID, fileName)
	return err
}
