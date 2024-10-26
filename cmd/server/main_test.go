package main

import (
    "bytes"
    "net/http"
    "net/http/httptest"
    "os"
    "testing"
)

// cleanup removes all uploaded files after an upload test
func cleanup() {
    if _, err := os.Stat(conf.StoreDir); err == nil {
        err := os.RemoveAll(conf.StoreDir)
        if err != nil {
            println("Error while cleaning up:", err)
        }
    }
}

// TestReadConfig checks if reading the configuration file works
func TestReadConfig(t *testing.T) {
    err := readConfig("config.toml", &conf)
    if err != nil {
        t.Fatal(err)
    }
}

// TestUploadWithHardcodedHMAC tests the upload using a hardcoded HMAC
func TestUploadWithHardcodedHMAC(t *testing.T) {
    defer cleanup()

    // Set config
    err := readConfig("config.toml", &conf)
    if err != nil {
        t.Fatal(err)
    }

    // Prepare test file
    fileContent, err := os.ReadFile("hmac.jpg")
    if err != nil {
        t.Fatal(err)
    }

    // Use the hardcoded HMAC value for testing
    hardcodedMAC := "aca8280410ea0fcbf787399ac4e1789e5286b4b7690925db87ba5de553fe9c7a"

    // Create request with the hardcoded MAC in the query parameter
    req, err := http.NewRequest("PUT", "/upload/badmuff/abc/hmac.jpg", bytes.NewBuffer(fileContent))
    if err != nil {
        t.Fatal(err)
    }

    q := req.URL.Query()
    q.Add("v", hardcodedMAC)
    req.URL.RawQuery = q.Encode()

    rr := httptest.NewRecorder()
    handler := http.HandlerFunc(handleRequest)

    // Send request and record response
    handler.ServeHTTP(rr, req)

    // Check status code
    if status := rr.Code; status != http.StatusCreated {
        t.Errorf("Expected status %v, but got %v. HTTP body: %s", http.StatusCreated, status, rr.Body.String())
    }
}
