package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/theheadmen/goDipl3/models"
)

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
