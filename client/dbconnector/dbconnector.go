package dbconnector

import (
	"database/sql"
	"errors"
	"log"

	"github.com/theheadmen/goDipl3/models"
)

func InitDB(db *sql.DB) {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS text_local_data (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			uuid INTEGER,
			user_id INTEGER,
			data TEXT,
			meta TEXT,
			created_at DATETIME,
			updated_at DATETIME
		);

		CREATE TABLE IF NOT EXISTS binary_local_data (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			uuid INTEGER,
			user_id INTEGER,
			data BLOB,
			meta TEXT,
			created_at DATETIME,
			updated_at DATETIME
		);

		CREATE TABLE IF NOT EXISTS bank_local_card (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			uuid INTEGER,
			user_id INTEGER,
			number TEXT,
			expiry TEXT,
			cvv TEXT,
			meta TEXT,
			created_at DATETIME,
			updated_at DATETIME
		);
	`)
	if err != nil {
		log.Fatal(err)
	}
}

func SaveTextData(db *sql.DB, data models.TextLocalData) error {
	_, err := db.Exec(`
		INSERT INTO text_local_data (uuid, user_id, data, meta, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, data.UUID, data.UserID, data.Data, data.Meta, data.CreatedAt, data.UpdatedAt)
	return err
}

func UpdateTextData(db *sql.DB, id int, data models.TextLocalData) error {
	// Проверяем, существует ли запись с таким id
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM text_local_data WHERE id=?)", id).Scan(&exists)
	if err != nil {
		return err
	}

	if exists {
		_, err := db.Exec(`
			UPDATE text_local_data
			SET uuid = ?, user_id = ?, data = ?, meta = ?, updated_at = ?
			WHERE id = ?
		`, data.UUID, data.UserID, data.Data, data.Meta, data.UpdatedAt, id)
		return err
	} else {
		return errors.New("data not found")
	}
}

func DeleteTextData(db *sql.DB, id int) error {
	_, err := db.Exec("DELETE FROM text_local_data WHERE id = ?", id)
	return err
}

func GetAllTextData(db *sql.DB) ([]models.TextLocalData, error) {
	rows, err := db.Query("SELECT id, uuid, user_id, data, meta, created_at, updated_at FROM text_local_data")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var dataList []models.TextLocalData
	for rows.Next() {
		var data models.TextLocalData
		err := rows.Scan(&data.ID, &data.UUID, &data.UserID, &data.Data, &data.Meta, &data.CreatedAt, &data.UpdatedAt)
		if err != nil {
			return nil, err
		}
		dataList = append(dataList, data)
	}

	return dataList, nil
}

func SaveBinaryData(db *sql.DB, data models.BinaryLocalData) error {
	_, err := db.Exec(`
		INSERT INTO binary_local_data (uuid, user_id, data, meta, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, data.UUID, data.UserID, data.Data, data.Meta, data.CreatedAt, data.UpdatedAt)
	return err
}

func UpdateBinaryData(db *sql.DB, id int, data models.BinaryLocalData) error {
	// Проверяем, существует ли запись с таким id
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM binary_local_data WHERE id=?)", id).Scan(&exists)
	if err != nil {
		return err
	}

	if exists {
		_, err := db.Exec(`
			UPDATE binary_local_data
			SET uuid = ?, user_id = ?, data = ?, meta = ?, updated_at = ?
			WHERE id = ?
		`, data.UUID, data.UserID, data.Data, data.Meta, data.UpdatedAt, id)
		return err
	} else {
		return errors.New("data not found")
	}
}

func DeleteBinaryData(db *sql.DB, id int) error {
	_, err := db.Exec("DELETE FROM binary_local_data WHERE id = ?", id)
	return err
}

func GetBinaryData(db *sql.DB, id int) (*models.BinaryLocalData, error) {
	var data models.BinaryLocalData
	err := db.QueryRow("SELECT id, uuid, user_id, data, meta, created_at, updated_at FROM binary_local_data WHERE id = ?", id).
		Scan(&data.ID, &data.UUID, &data.UserID, data.Data, &data.Meta, &data.CreatedAt, &data.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("data not found")
		}
		return nil, err
	}
	return &data, nil
}

func GetAllBinaryData(db *sql.DB) ([]models.BinaryLocalData, error) {
	rows, err := db.Query("SELECT id, uuid, user_id, data, meta, created_at, updated_at FROM binary_local_data")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var dataList []models.BinaryLocalData
	for rows.Next() {
		var data models.BinaryLocalData
		err := rows.Scan(&data.ID, &data.UUID, &data.UserID, &data.Data, &data.Meta, &data.CreatedAt, &data.UpdatedAt)
		if err != nil {
			return nil, err
		}
		dataList = append(dataList, data)
	}

	return dataList, nil
}

func SaveBankCard(db *sql.DB, data models.BankLocalCard) error {
	_, err := db.Exec(`
		INSERT INTO bank_local_card (uuid, user_id, number, expiry, cvv, meta, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, data.UUID, data.UserID, data.Number, data.Expiry, data.CVV, data.Meta, data.CreatedAt, data.UpdatedAt)
	return err
}

func UpdateBankData(db *sql.DB, id int, data models.BankLocalCard) error {
	// Проверяем, существует ли запись с таким id
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM bank_local_card WHERE id=?)", id).Scan(&exists)
	if err != nil {
		return err
	}

	if exists {
		_, err := db.Exec(`
			UPDATE bank_local_card
			SET uuid = ?, user_id = ?, number = ?, expiry = ?, cvv = ?, meta = ?, updated_at = ?
			WHERE id = ?
		`, data.UUID, data.UserID, data.Number, data.Expiry, data.CVV, data.Meta, data.UpdatedAt, id)
		return err
	} else {
		return errors.New("data not found")
	}
}

func DeleteBankData(db *sql.DB, id int) error {
	_, err := db.Exec("DELETE FROM bank_local_card WHERE id = ?", id)
	if err != nil {
		return err
	}
	return nil
}

func GetBankData(db *sql.DB, id int) (*models.BankLocalCard, error) {
	var data models.BankLocalCard
	err := db.QueryRow("SELECT id, uuid, user_id, number, expiry, cvv, meta, created_at, updated_at FROM bank_local_card WHERE id = ?", id).
		Scan(&data.ID, &data.UUID, &data.UserID, &data.Number, &data.Expiry, &data.CVV, &data.Meta, &data.CreatedAt, &data.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("data not found")
		}
		return nil, err
	}
	return &data, nil
}

func GetAllBankData(db *sql.DB) ([]models.BankLocalCard, error) {
	rows, err := db.Query("SELECT id, uuid, user_id, number, expiry, cvv, meta, created_at, updated_at FROM bank_local_card")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var dataList []models.BankLocalCard
	for rows.Next() {
		var data models.BankLocalCard
		err := rows.Scan(&data.ID, &data.UUID, &data.UserID, &data.Number, &data.Expiry, &data.CVV, &data.Meta, &data.CreatedAt, &data.UpdatedAt)
		if err != nil {
			return nil, err
		}
		dataList = append(dataList, data)
	}

	return dataList, nil
}
