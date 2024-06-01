package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestMain is a setup function for the test.
func TestMain(m *testing.M) {
	// Here you can set up any necessary dependencies, such as starting a server.

	// Run the tests.
	exitVal := m.Run()

	// Here you can tear down any dependencies, such as stopping the server.

	os.Exit(exitVal)
}

// TestRegister tests the registration process.
func TestRegister(t *testing.T) {
	username := "testuser"
	password := "testpass"

	// Execute the register command.
	cmd := exec.Command("go", "run", "main.go", "register", username, password)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("register command failed: %v", err)
	}

	// Check the output.
	expectedOutput := "User registered successfully.\n"
	if out.String() != expectedOutput {
		t.Errorf("expected output %q, got %q", expectedOutput, out.String())
	}
}

// TestLogin tests the login process.
func TestLogin(t *testing.T) {
	username := "testuser"
	password := "testpass"

	// Execute the login command.
	cmd := exec.Command("go", "run", "main.go", "login", username, password)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("login command failed: %v", err)
	}

	// Check the output.
	expectedOutput := "User logged in successfully.\n"
	if out.String() != expectedOutput {
		t.Errorf("expected output %q, got %q", expectedOutput, out.String())
	}
}

// TestStoreText tests the text data storage process.
func TestStoreText(t *testing.T) {
	dataType := "text"
	data := "test data"
	meta := "test meta"

	// Execute the store command.
	cmd := exec.Command("go", "run", "main.go", "store", dataType, data, "somekey", "--meta", meta)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("store command failed: %v", err)
	}

	// Check the output.
	expectedOutput := "Data stored successfully.\n"
	if out.String() != expectedOutput {
		t.Errorf("expected output %q, got %q", expectedOutput, out.String())
	}
}

// TestStoreBinary tests the data storage process for binary data.
func TestStoreBinary(t *testing.T) {
	dataType := "binary"
	data := "dGVzdCBkYXRh" // Base64 encoded "test data"
	meta := "test meta"

	// Execute the store command for binary data.
	cmd := exec.Command("go", "run", "main.go", "store", dataType, data, "somekey", "--meta", meta)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("store command failed: %v", err)
	}

	// Check the output.
	expectedOutput := "Data stored successfully.\n"
	if out.String() != expectedOutput {
		t.Errorf("expected output %q, got %q", expectedOutput, out.String())
	}
}

// TestStoreBankCard tests the data storage process for bank card data.
func TestStoreBankCard(t *testing.T) {
	dataType := "bankcard"
	data := "1234567812345678" // Example bank card number
	meta := "test meta"
	expiry := "12/24" // Example expiry date
	cvv := "123"      // Example CVV code

	// Execute the store command for bank card data.
	cmd := exec.Command("go", "run", "main.go", "store", dataType, data, "somekey", "--meta", meta, "--expiry", expiry, "--cvv", cvv)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("store command failed: %v", err)
	}

	// Check the output.
	expectedOutput := "Data stored successfully.\n"
	if out.String() != expectedOutput {
		t.Errorf("expected output %q, got %q", expectedOutput, out.String())
	}
}

// TestGetText tests the text data retrieval process.
func TestGetText(t *testing.T) {
	dataType := "text"

	// Execute the get command.
	cmd := exec.Command("go", "run", "main.go", "get", dataType, "somekey")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("get command failed: %v", err)
	}

	// Check the output.
	expectedOutput := "TextData: [{ID:1 UserID:1 Data:test data Meta:test meta"
	if !strings.Contains(out.String(), expectedOutput) {
		t.Errorf("expected output %q, got %q", expectedOutput, out.String())
	}
}

// TestGetBinary tests the binary data retrieval process.
func TestGetBinary(t *testing.T) {
	dataType := "binary"

	// Execute the get command.
	cmd := exec.Command("go", "run", "main.go", "get", dataType, "somekey")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("get command failed: %v", err)
	}

	// Check the output.
	expectedOutput := "BinaryData: [{ID:1 UserID:1 Data:[90 69 100 87 101 109 82 68 81 109 116 90 87 70 74 111]"
	if !strings.Contains(out.String(), expectedOutput) {
		t.Errorf("expected output %q, got %q", expectedOutput, out.String())
	}
}

// TestGetBankcard tests the bankcard data retrieval process.
func TestGetBankcard(t *testing.T) {
	dataType := "bankcard"

	// Execute the get command.
	cmd := exec.Command("go", "run", "main.go", "get", dataType, "somekey")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("get command failed: %v", err)
	}

	// Check the output.
	expectedOutput := "BankCard: [{ID:1 UserID:1 Number:1234567812345678 Expiry:12/24 CVV:123 Meta:test meta "
	if !strings.Contains(out.String(), expectedOutput) {
		t.Errorf("expected output %q, got %q", expectedOutput, out.String())
	}
}

// TestUpdateText tests the text data update process.
func TestUpdateText(t *testing.T) {
	dataType := "text"
	data := "upd data"
	meta := "upd meta"

	// Execute the store command.
	cmd := exec.Command("go", "run", "main.go", "update", dataType, "1", data, "somekey", "--meta", meta)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("update command failed: %v", err)
	}

	// Check the output.
	expectedOutput := "Data updated successfully.\n"
	if out.String() != expectedOutput {
		t.Errorf("expected output %q, got %q", expectedOutput, out.String())
	}

	// Execute the get command.
	cmd = exec.Command("go", "run", "main.go", "get", dataType, "somekey")
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("get command failed: %v", err)
	}

	// Check the output.
	expectedOutput = "TextData: [{ID:1 UserID:1 Data:upd data Meta:upd meta"
	if !strings.Contains(out.String(), expectedOutput) {
		t.Errorf("expected output %q, got %q", expectedOutput, out.String())
	}
}

// TestUpdateBinary tests the data update process for binary data.
func TestUpdateBinary(t *testing.T) {
	dataType := "binary"
	data := "ASDasd1234"
	meta := "upd test meta"

	// Execute the update command for binary data.
	cmd := exec.Command("go", "run", "main.go", "update", dataType, "1", data, "somekey", "--meta", meta)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("update command failed: %v", err)
	}

	// Check the output.
	expectedOutput := "Data updated successfully.\n"
	if out.String() != expectedOutput {
		t.Errorf("expected output %q, got %q", expectedOutput, out.String())
	}

	// Execute the get command.
	cmd = exec.Command("go", "run", "main.go", "get", dataType, "somekey")
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("get command failed: %v", err)
	}

	// Check the output.
	expectedOutput = "BinaryData: [{ID:1 UserID:1 Data:[81 86 78 69 89 88 78 107 77 84 73 122 78 65 61 61]"
	if !strings.Contains(out.String(), expectedOutput) {
		t.Errorf("expected output %q, got %q", expectedOutput, out.String())
	}
}

// TestUpdateBankCard tests the data update process for bank card data.
func TestUpdateBankCard(t *testing.T) {
	dataType := "bankcard"
	data := "1234567812345678" // Example bank card number
	meta := "upd test meta"
	expiry := "10/10" // Example expiry date
	cvv := "321"      // Example CVV code

	// Execute the update command for bank card data.
	cmd := exec.Command("go", "run", "main.go", "update", dataType, "1", data, "somekey", "--meta", meta, "--expiry", expiry, "--cvv", cvv)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("store command failed: %v", err)
	}

	// Check the output.
	expectedOutput := "Data updated successfully.\n"
	if out.String() != expectedOutput {
		t.Errorf("expected output %q, got %q", expectedOutput, out.String())
	}

	// Execute the get command.
	cmd = exec.Command("go", "run", "main.go", "get", dataType, "somekey")
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("get command failed: %v", err)
	}

	// Check the output.
	expectedOutput = "BankCard: [{ID:1 UserID:1 Number:1234567812345678 Expiry:10/10 CVV:321 Meta:upd test meta "
	if !strings.Contains(out.String(), expectedOutput) {
		t.Errorf("expected output %q, got %q", expectedOutput, out.String())
	}
}

// TestDeleteText tests the text data delete process.
func TestDeleteText(t *testing.T) {
	dataType := "text"

	// Execute the get command.
	cmd := exec.Command("go", "run", "main.go", "delete", dataType, "1")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("delete command failed: %v", err)
	}

	// Check the output.
	expectedOutput := "Data deleted successfully."
	if !strings.Contains(out.String(), expectedOutput) {
		t.Errorf("expected output %q, got %q", expectedOutput, out.String())
	}
}

// TestDeleteBinary tests the binary data delete process.
func TestDeleteBinary(t *testing.T) {
	dataType := "binary"

	// Execute the get command.
	cmd := exec.Command("go", "run", "main.go", "delete", dataType, "1")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("delete command failed: %v", err)
	}

	// Check the output.
	expectedOutput := "Data deleted successfully."
	if !strings.Contains(out.String(), expectedOutput) {
		t.Errorf("expected output %q, got %q", expectedOutput, out.String())
	}
}

// TestDeleteBankcard tests the bankcard data delete process.
func TestDeleteBankcard(t *testing.T) {
	dataType := "bankcard"

	// Execute the get command.
	cmd := exec.Command("go", "run", "main.go", "delete", dataType, "1")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("delete command failed: %v", err)
	}

	// Check the output.
	expectedOutput := "Data deleted successfully."
	if !strings.Contains(out.String(), expectedOutput) {
		t.Errorf("expected output %q, got %q", expectedOutput, out.String())
	}
}

// TestFilestore tests the file store process.
func TestFilestore(t *testing.T) {
	fileName := "./cookies.txt"

	// Execute the get command.
	cmd := exec.Command("go", "run", "main.go", "filestore", fileName)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("file store command failed: %v", err)
	}

	// Check the output.
	expectedOutput := "File stored successfully."
	if !strings.Contains(out.String(), expectedOutput) {
		t.Errorf("expected output %q, got %q", expectedOutput, out.String())
	}
}

// TestListfiles tests the get list of files process.
func TestListfiles(t *testing.T) {
	// Execute the get command.
	cmd := exec.Command("go", "run", "main.go", "listfiles")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("list files command failed: %v", err)
	}

	// Check the output.
	expectedOutput := "cookies"
	if !strings.Contains(out.String(), expectedOutput) {
		t.Errorf("expected output %q, got %q", expectedOutput, out.String())
	}
}

// TestGetFile tests the get file process.
func TestGetFile(t *testing.T) {
	// Execute the get command.
	cmd := exec.Command("go", "run", "main.go", "listfiles")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("list files command failed: %v", err)
	}

	fileName := out.String()
	fileName = strings.Replace(fileName, "\n", "", -1)
	localFileName := "./cok2.txt"

	// Execute the get command.
	cmd = exec.Command("go", "run", "main.go", "getfile", fileName, localFileName)
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("get store command failed: %v", err)
	}

	// Check the output.
	expectedOutput := "File saved to " + localFileName
	if !strings.Contains(out.String(), expectedOutput) {
		t.Errorf("expected output %q, got %q", expectedOutput, out.String())
	}

	file, err := os.Open(localFileName)
	if err != nil {
		t.Errorf("Error opening file: %s", err)
	}
	file.Close()
}

// TestDeleteFile tests the delete file process.
func TestDeleteFile(t *testing.T) {
	// Execute the get command.
	cmd := exec.Command("go", "run", "main.go", "listfiles")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("list files command failed: %v", err)
	}

	fileName := out.String()
	fileName = strings.Replace(fileName, "\n", "", -1)
	// Execute the get command.
	cmd = exec.Command("go", "run", "main.go", "deletefile", fileName)
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("get store command failed: %v", err)
	}

	// Check the output.
	expectedOutput := "File deleted successfully."
	if !strings.Contains(out.String(), expectedOutput) {
		t.Errorf("expected output %q, got %q", expectedOutput, out.String())
	}

	// Delete the file.
	localFileName := "./cok2.txt"
	err := os.Remove(localFileName)
	if err != nil {
		t.Fatalf("delete file command failed: %v", err)
	}
}
