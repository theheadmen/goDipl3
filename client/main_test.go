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
