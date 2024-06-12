package dbconnector

import (
	"database/sql"
	"errors"
	"log"
	"os"

	"github.com/theheadmen/goDipl3/models"
)

func initDB(db *sql.DB) {
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

type DBConnector struct {
	DB *sql.DB
}

func OpenDB() *DBConnector {
	// Open the database.
	db, err := sql.Open("sqlite3", "./gophkeeper.db")
	if err != nil {
		log.Printf("Failed to open database: %v", err)
		os.Exit(1)
	}

	// Initialize the database.
	initDB(db)
	return &DBConnector{DB: db}
}

func (dbconn DBConnector) SaveTextData(data models.TextLocalData) error {
	_, err := dbconn.DB.Exec(`
		INSERT INTO text_local_data (uuid, user_id, data, meta, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, data.UUID, data.UserID, data.Data, data.Meta, data.CreatedAt, data.UpdatedAt)
	return err
}

func (dbconn DBConnector) UpdateTextData(id int, data models.TextLocalData) error {
	// Проверяем, существует ли запись с таким id
	var exists bool
	err := dbconn.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM text_local_data WHERE id=?)", id).Scan(&exists)
	if err != nil {
		return err
	}

	if exists {
		_, err := dbconn.DB.Exec(`
			UPDATE text_local_data
			SET uuid = ?, user_id = ?, data = ?, meta = ?, updated_at = ?
			WHERE id = ?
		`, data.UUID, data.UserID, data.Data, data.Meta, data.UpdatedAt, id)
		return err
	} else {
		return errors.New("data not found")
	}
}

func (dbconn DBConnector) SaveAndUpdateTextData(datas []models.TextLocalData) error {
	// Запись TextLocalData в локальную БД клиента
	for _, data := range datas {
		// Проверка наличия данных в локальной БД
		var localData models.TextLocalData
		err := dbconn.DB.QueryRow("SELECT * FROM text_local_data WHERE uuid = ? AND user_id = ?", data.UUID, data.UserID).Scan(
			&localData.ID, &localData.UUID, &localData.UserID, &localData.Data, &localData.Meta, &localData.CreatedAt, &localData.UpdatedAt)
		if err != nil && err != sql.ErrNoRows {
			return err
		}

		// Если данные существуют и локальные данные старее, обновляем их
		if err == nil && localData.UpdatedAt.Before(data.UpdatedAt) {
			_, err := dbconn.DB.Exec("UPDATE text_local_data SET data = ?, meta = ?, updated_at = ? WHERE uuid = ? AND user_id = ?",
				data.Data, data.Meta, data.UpdatedAt, data.UUID, data.UserID)
			if err != nil {
				return err
			}
		} else if err == sql.ErrNoRows {
			// Если данных нет, вставляем новые данные
			_, err := dbconn.DB.Exec("INSERT INTO text_local_data (uuid, user_id, data, meta, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
				data.UUID, data.UserID, data.Data, data.Meta, data.CreatedAt, data.UpdatedAt)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (dbconn DBConnector) DeleteTextData(id int) error {
	_, err := dbconn.DB.Exec("DELETE FROM text_local_data WHERE id = ?", id)
	return err
}

func (dbconn DBConnector) GetAllTextData() ([]models.TextLocalData, error) {
	rows, err := dbconn.DB.Query("SELECT id, uuid, user_id, data, meta, created_at, updated_at FROM text_local_data")
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

func (dbconn DBConnector) SaveBinaryData(data models.BinaryLocalData) error {
	_, err := dbconn.DB.Exec(`
		INSERT INTO binary_local_data (uuid, user_id, data, meta, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, data.UUID, data.UserID, data.Data, data.Meta, data.CreatedAt, data.UpdatedAt)
	return err
}

func (dbconn DBConnector) UpdateBinaryData(id int, data models.BinaryLocalData) error {
	// Проверяем, существует ли запись с таким id
	var exists bool
	err := dbconn.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM binary_local_data WHERE id=?)", id).Scan(&exists)
	if err != nil {
		return err
	}

	if exists {
		_, err := dbconn.DB.Exec(`
			UPDATE binary_local_data
			SET uuid = ?, user_id = ?, data = ?, meta = ?, updated_at = ?
			WHERE id = ?
		`, data.UUID, data.UserID, data.Data, data.Meta, data.UpdatedAt, id)
		return err
	} else {
		return errors.New("data not found")
	}
}

func (dbconn DBConnector) SaveAndUpdateBinaryData(datas []models.BinaryLocalData) error {
	// Запись BinaryLocalData в локальную БД клиента
	for _, data := range datas {
		// Проверка наличия данных в локальной БД
		var localData models.BinaryLocalData
		err := dbconn.DB.QueryRow("SELECT * FROM binary_local_data WHERE uuid = ? AND user_id = ?", data.UUID, data.UserID).Scan(
			&localData.ID, &localData.UUID, &localData.UserID, &localData.Data, &localData.Meta, &localData.CreatedAt, &localData.UpdatedAt)
		if err != nil && err != sql.ErrNoRows {
			return err
		}

		// Если данные существуют и локальные данные старее, обновляем их
		if err == nil && localData.UpdatedAt.Before(data.UpdatedAt) {
			_, err := dbconn.DB.Exec("UPDATE binary_local_data SET data = ?, meta = ?, updated_at = ? WHERE uuid = ? AND user_id = ?",
				data.Data, data.Meta, data.UpdatedAt, data.UUID, data.UserID)
			if err != nil {
				return err
			}
		} else if err == sql.ErrNoRows {
			// Если данных нет, вставляем новые данные
			_, err := dbconn.DB.Exec("INSERT INTO binary_local_data (uuid, user_id, data, meta, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
				data.UUID, data.UserID, data.Data, data.Meta, data.CreatedAt, data.UpdatedAt)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (dbconn DBConnector) DeleteBinaryData(id int) error {
	_, err := dbconn.DB.Exec("DELETE FROM binary_local_data WHERE id = ?", id)
	return err
}

func (dbconn DBConnector) GetBinaryData(id int) (*models.BinaryLocalData, error) {
	var data models.BinaryLocalData
	err := dbconn.DB.QueryRow("SELECT id, uuid, user_id, data, meta, created_at, updated_at FROM binary_local_data WHERE id = ?", id).
		Scan(&data.ID, &data.UUID, &data.UserID, data.Data, &data.Meta, &data.CreatedAt, &data.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("data not found")
		}
		return nil, err
	}
	return &data, nil
}

func (dbconn DBConnector) GetAllBinaryData() ([]models.BinaryLocalData, error) {
	rows, err := dbconn.DB.Query("SELECT id, uuid, user_id, data, meta, created_at, updated_at FROM binary_local_data")
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

func (dbconn DBConnector) SaveBankCard(data models.BankLocalCard) error {
	_, err := dbconn.DB.Exec(`
		INSERT INTO bank_local_card (uuid, user_id, number, expiry, cvv, meta, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, data.UUID, data.UserID, data.Number, data.Expiry, data.CVV, data.Meta, data.CreatedAt, data.UpdatedAt)
	return err
}

func (dbconn DBConnector) UpdateBankData(id int, data models.BankLocalCard) error {
	// Проверяем, существует ли запись с таким id
	var exists bool
	err := dbconn.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM bank_local_card WHERE id=?)", id).Scan(&exists)
	if err != nil {
		return err
	}

	if exists {
		_, err := dbconn.DB.Exec(`
			UPDATE bank_local_card
			SET uuid = ?, user_id = ?, number = ?, expiry = ?, cvv = ?, meta = ?, updated_at = ?
			WHERE id = ?
		`, data.UUID, data.UserID, data.Number, data.Expiry, data.CVV, data.Meta, data.UpdatedAt, id)
		return err
	} else {
		return errors.New("data not found")
	}
}

func (dbconn DBConnector) SaveAndUpdateBankData(datas []models.BankLocalCard) error {
	// Запись BankLocalCard в локальную БД клиента
	for _, data := range datas {
		// Проверка наличия данных в локальной БД
		var localData models.BankLocalCard
		err := dbconn.DB.QueryRow("SELECT * FROM bank_local_card WHERE uuid = ? AND user_id = ?", data.UUID, data.UserID).Scan(
			&localData.ID, &localData.UUID, &localData.UserID, &localData.Number, &localData.Expiry, &localData.CVV, &localData.Meta, &localData.CreatedAt, &localData.UpdatedAt)
		if err != nil && err != sql.ErrNoRows {
			return err
		}

		// Если данные существуют и локальные данные старее, обновляем их
		if err == nil && localData.UpdatedAt.Before(data.UpdatedAt) {
			_, err := dbconn.DB.Exec("UPDATE bank_local_card SET number = ?, expiry = ?, cvv = ?, meta = ?, updated_at = ? WHERE uuid = ? AND user_id = ?",
				data.Number, data.Expiry, data.CVV, data.Meta, data.UpdatedAt, data.UUID, data.UserID)
			if err != nil {
				return err
			}
		} else if err == sql.ErrNoRows {
			// Если данных нет, вставляем новые данные
			_, err := dbconn.DB.Exec("INSERT INTO bank_local_card (uuid, user_id, number, expiry, cvv, meta, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
				data.UUID, data.UserID, data.Number, data.Expiry, data.CVV, data.Meta, data.CreatedAt, data.UpdatedAt)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (dbconn DBConnector) DeleteBankData(id int) error {
	_, err := dbconn.DB.Exec("DELETE FROM bank_local_card WHERE id = ?", id)
	if err != nil {
		return err
	}
	return nil
}

func (dbconn DBConnector) GetBankData(id int) (*models.BankLocalCard, error) {
	var data models.BankLocalCard
	err := dbconn.DB.QueryRow("SELECT id, uuid, user_id, number, expiry, cvv, meta, created_at, updated_at FROM bank_local_card WHERE id = ?", id).
		Scan(&data.ID, &data.UUID, &data.UserID, &data.Number, &data.Expiry, &data.CVV, &data.Meta, &data.CreatedAt, &data.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("data not found")
		}
		return nil, err
	}
	return &data, nil
}

func (dbconn DBConnector) GetAllBankData() ([]models.BankLocalCard, error) {
	rows, err := dbconn.DB.Query("SELECT id, uuid, user_id, number, expiry, cvv, meta, created_at, updated_at FROM bank_local_card")
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
