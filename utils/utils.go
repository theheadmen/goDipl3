package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
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
		return models.TextData{}, fmt.Errorf("invalid meta type for meta data")
	}
	return models.TextData{
		UserID:    userID,
		Data:      text,
		Meta:      meta,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
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
		UpdatedAt: time.Now(),
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
		UpdatedAt: time.Now(),
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

func ConvertTextToLocalData(textData []models.TextData) []models.TextLocalData {
	var textLocalData []models.TextLocalData
	for _, data := range textData {
		textLocalData = append(textLocalData, models.TextLocalData{
			UUID:      data.ID, // Используем ID в качестве UUID
			UserID:    data.UserID,
			Data:      data.Data,
			Meta:      data.Meta,
			CreatedAt: data.CreatedAt,
			UpdatedAt: data.UpdatedAt,
		})
	}
	return textLocalData
}

func ConvertLocalToTextData(textLocalData []models.TextLocalData) []models.TextData {
	var textData []models.TextData
	for _, data := range textLocalData {
		textData = append(textData, models.TextData{
			ID:        data.UUID, // Используем UUID в качестве ID
			UserID:    data.UserID,
			Data:      data.Data,
			Meta:      data.Meta,
			CreatedAt: data.CreatedAt,
			UpdatedAt: data.UpdatedAt,
		})
	}
	return textData
}

func ConvertBinaryToLocalData(binaryData []models.BinaryData) []models.BinaryLocalData {
	var localBinaryData []models.BinaryLocalData
	for _, data := range binaryData {
		localBinaryData = append(localBinaryData, models.BinaryLocalData{
			UUID:      data.ID, // Используем ID в качестве UUID
			UserID:    data.UserID,
			Data:      data.Data,
			Meta:      data.Meta,
			CreatedAt: data.CreatedAt,
			UpdatedAt: data.UpdatedAt,
		})
	}
	return localBinaryData
}

func ConvertLocalToBinaryData(binaryLocalData []models.BinaryLocalData) []models.BinaryData {
	var binaryData []models.BinaryData
	for _, data := range binaryLocalData {
		binaryData = append(binaryData, models.BinaryData{
			ID:        data.UUID, // Используем UUID в качестве ID
			UserID:    data.UserID,
			Data:      data.Data,
			Meta:      data.Meta,
			CreatedAt: data.CreatedAt,
			UpdatedAt: data.UpdatedAt,
		})
	}
	return binaryData
}

func ConvertBankToLocalData(bankData []models.BankCard) []models.BankLocalCard {
	var localBankData []models.BankLocalCard
	for _, data := range bankData {
		localBankData = append(localBankData, models.BankLocalCard{
			UUID:      data.ID, // Используем ID в качестве UUID
			UserID:    data.UserID,
			Number:    data.Number,
			Expiry:    data.Expiry,
			CVV:       data.CVV,
			Meta:      data.Meta,
			CreatedAt: data.CreatedAt,
			UpdatedAt: data.UpdatedAt,
		})
	}
	return localBankData
}

func ConvertLocalToBankData(bankLocalData []models.BankLocalCard) []models.BankCard {
	var bankData []models.BankCard
	for _, data := range bankLocalData {
		bankData = append(bankData, models.BankCard{
			ID:        data.UUID, // Используем ID в качестве UUID
			UserID:    data.UserID,
			Number:    data.Number,
			Expiry:    data.Expiry,
			CVV:       data.CVV,
			Meta:      data.Meta,
			CreatedAt: data.CreatedAt,
			UpdatedAt: data.UpdatedAt,
		})
	}
	return bankData
}

// Encrypt encrypts a string using a key of any length
func Encrypt(key []byte, text string) (string, error) {
	plaintext := []byte(text)

	// Pad key to block size
	key = padKeyToBlockSize(key, aes.BlockSize)

	// Create a new AES cipher using the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create a new Counter Mode block cipher
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	// Prepend the IV to the ciphertext
	ciphertextWithIV := append(iv, ciphertext...)

	return hex.EncodeToString(ciphertextWithIV), nil
}

// Decrypt decrypts a string using a key of any length
func Decrypt(key []byte, cryptoText string) (string, error) {
	ciphertextWithIV, err := hex.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}

	// Pad key to block size
	key = padKeyToBlockSize(key, aes.BlockSize)

	// Create a new AES cipher using the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Extract the IV from the ciphertext
	if len(ciphertextWithIV) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv := ciphertextWithIV[:aes.BlockSize]
	ciphertext := ciphertextWithIV[aes.BlockSize:]

	// Create a new Counter Mode block cipher
	stream := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return string(plaintext), nil
}

// padKeyToBlockSize pads the key to the block size if it's shorter
func padKeyToBlockSize(key []byte, blockSize int) []byte {
	for len(key) < blockSize {
		key = append(key, 0)
	}
	return key[:blockSize]
}

func DecryptTextData(textData []models.TextData, key []byte) error {
	for i := range textData {
		decrData, err := Decrypt(key, textData[i].Data)
		if err != nil {
			return err
		}

		decrMeta, err := Decrypt(key, textData[i].Meta)
		if err != nil {
			return err
		}
		textData[i].Data = decrData
		textData[i].Meta = decrMeta
	}
	return nil
}

func DecryptBinaryData(binaryData []models.BinaryData, key []byte) error {
	for i := range binaryData {
		decrData, err := Decrypt(key, string(binaryData[i].Data))
		if err != nil {
			return err
		}
		decrMeta, err := Decrypt(key, binaryData[i].Meta)
		if err != nil {
			return err
		}
		binaryData[i].Data = []byte(decrData)
		binaryData[i].Meta = decrMeta
	}
	return nil
}

func DecryptBankData(bankCard []models.BankCard, key []byte) error {
	for i := range bankCard {
		decrNumber, err := Decrypt(key, bankCard[i].Number)
		if err != nil {
			return err
		}

		decrExpiry, err := Decrypt(key, bankCard[i].Expiry)
		if err != nil {
			return err
		}

		decrCVV, err := Decrypt(key, bankCard[i].CVV)
		if err != nil {
			return err
		}

		decrMeta, err := Decrypt(key, bankCard[i].Meta)
		if err != nil {
			return err
		}
		bankCard[i].Number = decrNumber
		bankCard[i].Expiry = decrExpiry
		bankCard[i].CVV = decrCVV
		bankCard[i].Meta = decrMeta
	}
	return nil
}
