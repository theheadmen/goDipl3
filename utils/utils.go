package utils

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/theheadmen/goDipl3/models"
)

// createTextData creates a TextData object from the given data.
func CreateTextData(userID int, data map[string]interface{}) (models.TextData, error) {
	text, ok := data["data"].(string)
	if !ok {
		return models.TextData{}, fmt.Errorf("invalid data type for text data")
	}
	meta, ok := data["meta"].(string)
	if !ok {
		return models.TextData{}, fmt.Errorf("invalid data type for meta data")
	}
	return models.TextData{
		UserID:    userID,
		Data:      text,
		Meta:      meta,
		CreatedAt: time.Now(),
	}, nil
}

// createBinaryData creates a BinaryData object from the given data.
func CreateBinaryData(userID int, data map[string]interface{}) (models.BinaryData, error) {
	binary, ok := data["data"].(string)
	if !ok {
		return models.BinaryData{}, fmt.Errorf("invalid data type for binary data")
	}
	meta, ok := data["meta"].(string)
	if !ok {
		return models.BinaryData{}, fmt.Errorf("invalid data type for meta data")
	}
	return models.BinaryData{
		UserID:    userID,
		Data:      []byte(binary),
		Meta:      meta,
		CreatedAt: time.Now(),
	}, nil
}

// createBankCard creates a BankCard object from the given data.
func CreateBankCard(userID int, data map[string]interface{}) (models.BankCard, error) {
	number, ok := data["number"].(string)
	if !ok {
		return models.BankCard{}, fmt.Errorf("invalid data type for card number")
	}
	expiry, ok := data["expiry"].(string)
	if !ok {
		return models.BankCard{}, fmt.Errorf("invalid data type for card expiry")
	}
	cvv, ok := data["cvv"].(string)
	if !ok {
		return models.BankCard{}, fmt.Errorf("invalid data type for card cvv")
	}
	meta, ok := data["meta"].(string)
	if !ok {
		return models.BankCard{}, fmt.Errorf("invalid data type for meta data")
	}
	return models.BankCard{
		UserID:    userID,
		Number:    number,
		Expiry:    expiry,
		CVV:       cvv,
		Meta:      meta,
		CreatedAt: time.Now(),
	}, nil
}

func SendRequest(baseURL *url.URL, body io.Reader, reqType string, contentType string, withCookie bool, authCookies []*http.Cookie) (*http.Response, error) {
	// Создаем новый транспорт, который будет использовать TLS
	// Используйте InsecureSkipVerify: false для рабочей среды
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(reqType, baseURL.String(), body)
	if err != nil {
		return nil, err
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	// Установка cookie в заголовки запроса
	if withCookie {
		for _, cookie := range authCookies {
			req.AddCookie(cookie)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}