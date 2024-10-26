package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"
)

// Cleans up the store directory after test execution
func cleanup() {
	if _, err := os.Stat(conf.StoreDir); err == nil {
		err := os.RemoveAll(conf.StoreDir)
		if err != nil {
			println("Error while cleaning up:", err)
		}
	}
}

// Test configuration reading
func TestReadConfig(t *testing.T) {
	err := readConfig("config.toml", &conf)
	if err != nil {
		t.Fatal("Failed to read config:", err)
	}
}

// Test HMAC upload with expected static HMAC value
func TestUploadWithStaticHMAC(t *testing.T) {
	defer cleanup()

	// Read configuration
	err := readConfig("config.toml", &conf)
	if err != nil {
		t.Fatal("Failed to read config:", err)
	}

	// Prepare file content for upload
	fileContent, err := os.ReadFile("hmac.jpg")
	if err != nil {
		t.Fatal("Failed to read test file:", err)
	}

	// Generate unique upload path based on test requirements
	uniqueUploadPath := "bd69c99f1c18b412f3a3e9e1a6009648f6dce67650dc9936054f34332875c7e6/hmac.jpg"
	fileLength := strconv.Itoa(len(fileContent))

	// Static expected HMAC for comparison (update if necessary)
	expectedHMAC := "aca8280410ea0fcbf787399ac4e1789e5286b4b7690925db87ba5de553fe9c7a"

	// HMAC calculation for test
	mac := hmac.New(sha256.New, []byte(conf.Secret))
	message := uniqueUploadPath + fileLength
	mac.Write([]byte(message))
	calculatedHMAC := hex.EncodeToString(mac.Sum(nil))

	t.Logf("Expected Static HMAC: %s", expectedHMAC)
	t.Logf("Upload Path: %s", uniqueUploadPath)
	t.Logf("File Length: %s", fileLength)
	t.Logf("Message for HMAC Calculation: %s", message)
	t.Logf("Calculated HMAC: %s", calculatedHMAC)

	// Assert HMAC correctness before proceeding with request
	if calculatedHMAC != expectedHMAC {
		t.Fatalf("Calculated HMAC does not match known HMAC. Expected: %s, Got: %s", expectedHMAC, calculatedHMAC)
	}

	// Prepare HTTP request
	req, err := http.NewRequest("PUT", "/upload/"+uniqueUploadPath, bytes.NewBuffer(fileContent))
	if err != nil {
		t.Fatal("Failed to create HTTP request:", err)
	}

	// Attach HMAC to request as query parameter
	q := req.URL.Query()
	q.Add("v", calculatedHMAC)
	req.URL.RawQuery = q.Encode()

	// Create HTTP recorder and handler
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleRequest)

	// Retry logic for upload
	maxRetries := 5
	for i := 0; i < maxRetries; i++ {
		handler.ServeHTTP(rr, req)

		// If request succeeds, break out of retry loop
		if rr.Code == http.StatusCreated {
			break
		}
		// Wait before retrying
		time.Sleep(500 * time.Millisecond)
	}

	// Final assertion
	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("Expected status %v, but got %v. HTTP body: %s", http.StatusCreated, status, rr.Body.String())
	}
}
