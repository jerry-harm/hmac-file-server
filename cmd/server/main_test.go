package main

import (
    "bytes"
    "io"
    "net/http"
    "net/http/httptest"
    "os"
    "path/filepath"
    "testing"

    "github.com/sirupsen/logrus"
)

func mockUpload() {
    os.MkdirAll(filepath.Join(conf.StoreDir, "thomas/abc/"), os.ModePerm)
    from, err := os.Open("./catmetal.jpg")
    if err != nil {
        logrus.Fatal(err)
    }
    defer from.Close()

    to, err := os.OpenFile(filepath.Join(conf.StoreDir, "thomas/abc/catmetal.jpg"), os.O_RDWR|os.O_CREATE, 0660)
    if err != nil {
        logrus.Fatal(err)
    }
    defer to.Close()

    _, err = io.Copy(to, from)
    if err != nil {
        logrus.Fatal(err)
    }
}

/*
 * Remove all uploaded files after an upload test
 */
func cleanup() {
    // Clean up
    if _, err := os.Stat(conf.StoreDir); err == nil {
        err := os.RemoveAll(conf.StoreDir)
        if err != nil {
            logrus.Println("Error while cleaning up:", err)
        }
    }
}

/*
 * Test if reading the config file works
 */
func TestReadConfig(t *testing.T) {
    // Set config
    err := readConfig("config.toml", &conf)
    if err != nil {
        t.Fatal(err)
    }

    logrus.SetLevel(logrus.FatalLevel)
}

/*
 * Run an upload test using the v1 / v MAC parameter
 */
func TestUploadValidV1(t *testing.T) {
    // Remove uploaded file after test
    defer cleanup()

    // Set config
    err := readConfig("config.toml", &conf)
    if err != nil {
        t.Fatal(err)
    }

    // Read catmetal file
    catMetalFile, err := os.ReadFile("catmetal.jpg")
    if err != nil {
        t.Fatal(err)
    }

    // Create request
    req, err := http.NewRequest("PUT", "/upload/thomas/abc/catmetal.jpg", bytes.NewBuffer(catMetalFile))
    q := req.URL.Query()
    q.Add("v", "7b8879e2d1c733b423a70cde30cecc3a3c64a03f790d1b5bcbb2a6aca52b477e")
    req.URL.RawQuery = q.Encode()

    if err != nil {
        t.Fatal(err)
    }

    rr := httptest.NewRecorder()
    handler := http.HandlerFunc(handleRequest)

    // Send request and record response
    handler.ServeHTTP(rr, req)

    // Check status code
    if status := rr.Code; status != http.StatusCreated {
        t.Errorf("handler returned wrong status code: got %v want %v. HTTP body: %s", status, http.StatusCreated, rr.Body.String())
    }
}

// ... Weitere Testfunktionen ...
