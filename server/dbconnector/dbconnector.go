package dbconnector

import (
	"database/sql"
	"errors"
	"log"
	"time"

	"github.com/theheadmen/goDipl3/models"
)

type DBConnector struct {
	db *sql.DB
}

// NewDBConnector creates a new DBConnector instance with the given database connection.
func NewDBConnector(db *sql.DB) *DBConnector {
	return &DBConnector{db: db}
}

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
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
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
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
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
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
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
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(user_id) REFERENCES users(id)
		)
	`)
	if err != nil {
		log.Fatalf("Failed to create text_data table: %v", err)
	}

	log.Println("DB init success")
}

func (dbconn DBConnector) CheckUserExists(user models.User) error {
	var existingUserID int
	err := dbconn.db.QueryRow("SELECT id FROM users WHERE username = ?", user.Username).Scan(&existingUserID)
	return err
}

func (dbconn DBConnector) InsertNewUser(user models.User) (sql.Result, error) {
	result, err := dbconn.db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", user.Username, user.Password)
	return result, err
}

func (dbconn DBConnector) GetUserByName(username string) (models.User, error) {
	var storedUser models.User
	err := dbconn.db.QueryRow("SELECT id, username, password FROM users WHERE username = ?", username).Scan(&storedUser.ID, &storedUser.Username, &storedUser.Password)
	return storedUser, err
}

// storeTextData stores text data for the given user.
func (dbconn DBConnector) StoreTextData(textData models.TextData) error {
	log.Println("store text", textData)

	_, err := dbconn.db.Exec("INSERT INTO text_data (user_id, data, meta, created_at, updated_at) VALUES (?, ?, ?, ?, ?)", textData.UserID, textData.Data, textData.Meta, textData.CreatedAt, textData.UpdatedAt)
	return err
}

// storeBinaryData stores binary data for the given user.
func (dbconn DBConnector) StoreBinaryData(binaryData models.BinaryData) error {
	log.Println("store binary", binaryData)

	_, err := dbconn.db.Exec("INSERT INTO binary_data (user_id, data, meta, created_at, updated_at) VALUES (?, ?, ?, ?, ?)", binaryData.UserID, binaryData.Data, binaryData.Meta, binaryData.CreatedAt, binaryData.UpdatedAt)
	return err
}

// storeBankCard stores bank card data for the given user.
func (dbconn DBConnector) StoreBankCard(bankCard models.BankCard) error {
	log.Println("store bank card", bankCard)

	_, err := dbconn.db.Exec("INSERT INTO bank_cards (user_id, number, expiry, cvv, meta, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)", bankCard.UserID, bankCard.Number, bankCard.Expiry, bankCard.CVV, bankCard.Meta, bankCard.CreatedAt, bankCard.UpdatedAt)
	return err
}

func (dbconn DBConnector) SaveAndUpdateTextData(datas []models.TextData) error {
	for _, data := range datas {
		// Проверка наличия данных в БД
		var localData models.TextData
		err := dbconn.db.QueryRow("SELECT * FROM text_data WHERE id = ? AND user_id = ?", data.ID, data.UserID).Scan(
			&localData.ID, &localData.UserID, &localData.Data, &localData.Meta, &localData.CreatedAt, &localData.UpdatedAt)
		if err != nil && err != sql.ErrNoRows {
			return err
		}

		// Если данные существуют и локальные данные старее, обновляем их
		if err == nil && localData.UpdatedAt.Before(data.UpdatedAt) {
			_, err := dbconn.db.Exec("UPDATE text_data SET data = ?, meta = ?, updated_at = ? WHERE id = ? AND user_id = ?",
				data.Data, data.Meta, data.UpdatedAt, data.ID, data.UserID)
			if err != nil {
				return err
			}
		} else if err == sql.ErrNoRows {
			// Если данных нет, вставляем новые данные
			_, err := dbconn.db.Exec("INSERT INTO text_data (user_id, data, meta, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
				data.UserID, data.Data, data.Meta, data.CreatedAt, data.UpdatedAt)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (dbconn DBConnector) SaveAndUpdateBinaryData(datas []models.BinaryData) error {
	for _, data := range datas {
		// Проверка наличия данных в локальной БД
		var localData models.BinaryData
		err := dbconn.db.QueryRow("SELECT * FROM binary_data WHERE id = ? AND user_id = ?", data.ID, data.UserID).Scan(
			&localData.ID, &localData.UserID, &localData.Data, &localData.Meta, &localData.CreatedAt, &localData.UpdatedAt)
		if err != nil && err != sql.ErrNoRows {
			return err
		}

		// Если данные существуют и локальные данные старее, обновляем их
		if err == nil && localData.UpdatedAt.Before(data.UpdatedAt) {
			_, err := dbconn.db.Exec("UPDATE binary_data SET data = ?, meta = ?, updated_at = ? WHERE id = ? AND user_id = ?",
				data.Data, data.Meta, data.UpdatedAt, data.ID, data.UserID)
			if err != nil {
				return err
			}
		} else if err == sql.ErrNoRows {
			// Если данных нет, вставляем новые данные
			_, err := dbconn.db.Exec("INSERT INTO binary_data (user_id, data, meta, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
				data.UserID, data.Data, data.Meta, data.CreatedAt, data.UpdatedAt)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (dbconn DBConnector) SaveAndUpdateBankData(datas []models.BankCard) error {
	for _, data := range datas {
		// Проверка наличия данных в локальной БД
		var localData models.BankCard
		err := dbconn.db.QueryRow("SELECT * FROM bank_cards WHERE id = ? AND user_id = ?", data.ID, data.UserID).Scan(
			&localData.ID, &localData.UserID, &localData.Number, &localData.Expiry, &localData.CVV, &localData.Meta, &localData.CreatedAt, &localData.UpdatedAt)
		if err != nil && err != sql.ErrNoRows {
			return err
		}

		// Если данные существуют и локальные данные старее, обновляем их
		if err == nil && localData.UpdatedAt.Before(data.UpdatedAt) {
			_, err := dbconn.db.Exec("UPDATE bank_cards SET number = ?, expiry = ?, cvv = ?, meta = ?, updated_at = ? WHERE id = ? AND user_id = ?",
				data.Number, data.Expiry, data.CVV, data.Meta, data.UpdatedAt, data.ID, data.UserID)
			if err != nil {
				return err
			}
		} else if err == sql.ErrNoRows {
			// Если данных нет, вставляем новые данные
			_, err := dbconn.db.Exec("INSERT INTO bank_cards (user_id, number, expiry, cvv, meta, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
				data.UserID, data.Number, data.Expiry, data.CVV, data.Meta, data.CreatedAt, data.UpdatedAt)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// storeTextDataArray stores an array of text data for the given user.
func (dbconn DBConnector) StoreTextDataArray(textDataArray []models.TextData) error {
	log.Println("store text array", textDataArray)

	tx, err := dbconn.db.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare("INSERT INTO text_data (user_id, data, meta, created_at, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT (user_id, id) DO UPDATE SET data = ?, meta = ?, updated_at = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, textData := range textDataArray {
		_, err = stmt.Exec(textData.UserID, textData.Data, textData.Meta, textData.CreatedAt, textData.UpdatedAt, textData.Data, textData.Meta, textData.UpdatedAt)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}

// storeBinaryDataArray stores an array of binary data for the given user.
func (dbconn DBConnector) StoreBinaryDataArray(binaryDataArray []models.BinaryData) error {
	log.Println("store binary array", binaryDataArray)

	tx, err := dbconn.db.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare("INSERT INTO binary_data (user_id, data, meta, created_at, updated_at) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, binaryData := range binaryDataArray {
		_, err = stmt.Exec(binaryData.UserID, binaryData.Data, binaryData.Meta, binaryData.CreatedAt, binaryData.UpdatedAt)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}

// storeBankCardArray stores an array of bank card data for the given user.
func (dbconn DBConnector) StoreBankCardArray(bankCardArray []models.BankCard) error {
	log.Println("store bank card array", bankCardArray)

	tx, err := dbconn.db.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare("INSERT INTO bank_cards (user_id, number, expiry, cvv, meta, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, bankCard := range bankCardArray {
		_, err = stmt.Exec(bankCard.UserID, bankCard.Number, bankCard.Expiry, bankCard.CVV, bankCard.Meta, bankCard.CreatedAt, bankCard.UpdatedAt)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}

// retrieveTextData retrieves text data for the given user.
func (dbconn DBConnector) RetrieveTextData(userID int) ([]models.TextData, error) {
	rows, err := dbconn.db.Query("SELECT id, user_id, data, meta, created_at, updated_at FROM text_data WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var textDataList []models.TextData
	for rows.Next() {
		var textData models.TextData
		err := rows.Scan(&textData.ID, &textData.UserID, &textData.Data, &textData.Meta, &textData.CreatedAt, &textData.UpdatedAt)
		if err != nil {
			return nil, err
		}
		textDataList = append(textDataList, textData)
	}

	return textDataList, nil
}

// retrieveBinaryData retrieves binary data for the given user.
func (dbconn DBConnector) RetrieveBinaryData(userID int) ([]models.BinaryData, error) {
	rows, err := dbconn.db.Query("SELECT id, user_id, data, meta, created_at, updated_at FROM binary_data WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var binaryDataList []models.BinaryData
	for rows.Next() {
		var binaryData models.BinaryData
		err := rows.Scan(&binaryData.ID, &binaryData.UserID, &binaryData.Data, &binaryData.Meta, &binaryData.CreatedAt, &binaryData.UpdatedAt)
		if err != nil {
			return nil, err
		}
		binaryDataList = append(binaryDataList, binaryData)
	}

	return binaryDataList, nil
}

// retrieveBankCards retrieves bank card data for the given user.
func (dbconn DBConnector) RetrieveBankCards(userID int) ([]models.BankCard, error) {
	rows, err := dbconn.db.Query("SELECT id, user_id, number, expiry, cvv, meta, created_at, updated_at FROM bank_cards WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bankCardsList []models.BankCard
	for rows.Next() {
		var bankCard models.BankCard
		err := rows.Scan(&bankCard.ID, &bankCard.UserID, &bankCard.Number, &bankCard.Expiry, &bankCard.CVV, &bankCard.Meta, &bankCard.CreatedAt, &bankCard.UpdatedAt)
		if err != nil {
			return nil, err
		}
		bankCardsList = append(bankCardsList, bankCard)
	}

	return bankCardsList, nil
}

// deleteTextData deletes text data for the given user.
func (dbconn DBConnector) DeleteTextData(userID int, dataID string) error {
	// Check if the data exists
	var count int
	err := dbconn.db.QueryRow("SELECT COUNT(*) FROM text_data WHERE user_id = ? AND id = ?", userID, dataID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("data not found")
	}

	// Delete the data
	_, err = dbconn.db.Exec("DELETE FROM text_data WHERE user_id = ? AND id = ?", userID, dataID)
	return err
}

// deleteBinaryData deletes binary data for the given user.
func (dbconn DBConnector) DeleteBinaryData(userID int, dataID string) error {
	// Check if the data exists
	var count int
	err := dbconn.db.QueryRow("SELECT COUNT(*) FROM binary_data WHERE user_id = ? AND id = ?", userID, dataID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("data not found")
	}

	// Delete the data
	_, err = dbconn.db.Exec("DELETE FROM binary_data WHERE user_id = ? AND id = ?", userID, dataID)
	return err
}

// deleteBankCard deletes bank card data for the given user.
func (dbconn DBConnector) DeleteBankCard(userID int, dataID string) error {
	// Check if the data exists
	var count int
	err := dbconn.db.QueryRow("SELECT COUNT(*) FROM bank_cards WHERE user_id = ? AND id = ?", userID, dataID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("data not found")
	}

	// Delete the data
	_, err = dbconn.db.Exec("DELETE FROM bank_cards WHERE user_id = ? AND id = ?", userID, dataID)
	return err
}

// updateTextData updates text data for the given user.
func (dbconn DBConnector) UpdateTextData(userID int, dataID string, data map[string]interface{}) error {
	// Check if the data exists.
	var exists bool
	err := dbconn.db.QueryRow("SELECT EXISTS(SELECT 1 FROM text_data WHERE id = ? AND user_id = ?)", dataID, userID).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("data not found")
	}

	textData := models.TextData{
		UserID:    userID,
		Data:      data["data"].(string),
		Meta:      data["meta"].(string),
		UpdatedAt: time.Now(),
	}
	log.Println("update text", textData)

	_, err = dbconn.db.Exec("UPDATE text_data SET data = ?, meta = ?, updated_at = ? WHERE id = ? AND user_id = ?", textData.Data, textData.Meta, textData.UpdatedAt, dataID, userID)
	return err
}

// updateBinaryData updates binary data for the given user.
func (dbconn DBConnector) UpdateBinaryData(userID int, dataID string, data map[string]interface{}) error {
	// Check if the data exists.
	var exists bool
	err := dbconn.db.QueryRow("SELECT EXISTS(SELECT 1 FROM binary_data WHERE id = ? AND user_id = ?)", dataID, userID).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("data not found")
	}

	binaryData := models.BinaryData{
		UserID:    userID,
		Data:      []byte(data["data"].(string)),
		Meta:      data["meta"].(string),
		UpdatedAt: time.Now(),
	}

	_, err = dbconn.db.Exec("UPDATE binary_data SET data = ?, meta = ?, updated_at = ? WHERE id = ? AND user_id = ?", binaryData.Data, binaryData.Meta, binaryData.UpdatedAt, dataID, userID)
	return err
}

// updateBankCard updates bank card data for the given user.
func (dbconn DBConnector) UpdateBankCard(userID int, dataID string, data map[string]interface{}) error {
	// Check if the data exists.
	var exists bool
	err := dbconn.db.QueryRow("SELECT EXISTS(SELECT 1 FROM bank_cards WHERE id = ? AND user_id = ?)", dataID, userID).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("data not found")
	}

	bankCard := models.BankCard{
		UserID:    userID,
		Number:    data["number"].(string),
		Expiry:    data["expiry"].(string),
		CVV:       data["cvv"].(string),
		Meta:      data["meta"].(string),
		UpdatedAt: time.Now(),
	}

	_, err = dbconn.db.Exec("UPDATE bank_cards SET number = ?, expiry = ?, cvv = ?, meta = ?, updated_at = ? WHERE id = ? AND user_id = ?", bankCard.Number, bankCard.Expiry, bankCard.CVV, bankCard.Meta, bankCard.UpdatedAt, dataID, userID)
	return err
}

// storeFileData stores file data for the given user.
func (dbconn DBConnector) StoreFileData(userID int, filePath string, fileName string) error {
	fileData := models.FileData{
		UserID:    userID,
		FilePath:  filePath,
		FileName:  fileName,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_, err := dbconn.db.Exec("INSERT INTO file_data (user_id, file_path, file_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)", fileData.UserID, fileData.FilePath, fileData.FileName, fileData.CreatedAt, fileData.UpdatedAt)
	return err
}

// getFilePath retrieves the file path from the database.
func (dbconn DBConnector) GetFilePath(userID int, fileName string) (string, error) {
	var filePath string
	err := dbconn.db.QueryRow("SELECT file_path FROM file_data WHERE user_id = ? AND file_name = ?", userID, fileName).Scan(&filePath)
	if err != nil {
		return "", err
	}
	return filePath, nil
}

// getFileNames retrieves the list of file names from the database.
func (dbconn DBConnector) GetFileNames(userID int) ([]string, error) {
	rows, err := dbconn.db.Query("SELECT file_name FROM file_data WHERE user_id = ?", userID)
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
func (dbconn DBConnector) DeleteFileData(userID int, fileName string) error {
	_, err := dbconn.db.Exec("DELETE FROM file_data WHERE user_id = ? AND file_name = ?", userID, fileName)
	return err
}
