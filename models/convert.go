package models

import (
	"fmt"
	"time"
)

// createTextData creates a TextData object from the given data.
func CreateTextData(userID int, data map[string]interface{}) (TextData, error) {
	text, ok := data["data"].(string)
	if !ok {
		return TextData{}, fmt.Errorf("invalid data type for text data")
	}
	meta, ok := data["meta"].(string)
	if !ok {
		return TextData{}, fmt.Errorf("invalid meta type for meta data")
	}
	return TextData{
		UserID:    userID,
		Data:      text,
		Meta:      meta,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}, nil
}

// createBinaryData creates a BinaryData object from the given data.
func CreateBinaryData(userID int, data map[string]interface{}) (BinaryData, error) {
	binary, ok := data["data"].(string)
	if !ok {
		return BinaryData{}, fmt.Errorf("invalid data type for binary data")
	}
	meta, ok := data["meta"].(string)
	if !ok {
		return BinaryData{}, fmt.Errorf("invalid data type for meta data")
	}
	return BinaryData{
		UserID:    userID,
		Data:      []byte(binary),
		Meta:      meta,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}, nil
}

// createBankCard creates a BankCard object from the given data.
func CreateBankCard(userID int, data map[string]interface{}) (BankCard, error) {
	number, ok := data["number"].(string)
	if !ok {
		return BankCard{}, fmt.Errorf("invalid data type for card number")
	}
	expiry, ok := data["expiry"].(string)
	if !ok {
		return BankCard{}, fmt.Errorf("invalid data type for card expiry")
	}
	cvv, ok := data["cvv"].(string)
	if !ok {
		return BankCard{}, fmt.Errorf("invalid data type for card cvv")
	}
	meta, ok := data["meta"].(string)
	if !ok {
		return BankCard{}, fmt.Errorf("invalid data type for meta data")
	}
	return BankCard{
		UserID:    userID,
		Number:    number,
		Expiry:    expiry,
		CVV:       cvv,
		Meta:      meta,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}, nil
}

// ConvertTextToLocalData convert TextData to TextLocalData
func ConvertTextToLocalData(textData []TextData) []TextLocalData {
	var textLocalData []TextLocalData
	for _, data := range textData {
		textLocalData = append(textLocalData, TextLocalData{
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

// ConvertLocalToTextData convert TextLocalData to TextData
func ConvertLocalToTextData(textLocalData []TextLocalData) []TextData {
	var textData []TextData
	for _, data := range textLocalData {
		textData = append(textData, TextData{
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

// ConvertBinaryToLocalData convert BinaryData to BinaryLocalData
func ConvertBinaryToLocalData(binaryData []BinaryData) []BinaryLocalData {
	var localBinaryData []BinaryLocalData
	for _, data := range binaryData {
		localBinaryData = append(localBinaryData, BinaryLocalData{
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

// ConvertLocalToBinaryData convert BinaryLocalData to BinaryData
func ConvertLocalToBinaryData(binaryLocalData []BinaryLocalData) []BinaryData {
	var binaryData []BinaryData
	for _, data := range binaryLocalData {
		binaryData = append(binaryData, BinaryData{
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

// ConvertBankToLocalData convert BankCard to BankLocalCard
func ConvertBankToLocalData(bankData []BankCard) []BankLocalCard {
	var localBankData []BankLocalCard
	for _, data := range bankData {
		localBankData = append(localBankData, BankLocalCard{
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

// ConvertLocalToBankData convert BankLocalCard to BankCard
func ConvertLocalToBankData(bankLocalData []BankLocalCard) []BankCard {
	var bankData []BankCard
	for _, data := range bankLocalData {
		bankData = append(bankData, BankCard{
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
