package main

/*
 * Manual testing with CURL
 * Send with:
 * curl -X PUT "http://localhost:5050/upload/thomas/abc/catmetal.jpg?v=7b8879e2d1c733b423a70cde30cecc3a3c64a03f790d1b5bcbb2a6aca52b477e" --data-binary '@catmetal.jpg'
 * HMAC: 7b8879e2d1c733b423a70cde30cecc3a3c64a03f790d1b5bcbb2a6aca52b477e
 */

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
		log.Fatal(err)
	}
	defer from.Close()

	to, err := os.OpenFile(filepath.Join(conf.StoreDir, "thomas/abc/catmetal.jpg"), os.O_RDWR|os.O_CREATE, 0660)
	if err != nil {
		log.Fatal(err)
	}
	defer to.Close()

	_, err = io.Copy(to, from)
	if err != nil {
		log.Fatal(err)
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
			log.Println("Error while cleaning up:", err)
		}
	}
}

/*
 * Test if reading the config file works
 */
func TestReadConfig(t *testing.T) {
	// Set config
	err := readConfig("config.toml")
	if err != nil {
		t.Fatal(err)
	}

	log.SetLevel(logrus.FatalLevel)
}

/*
 * Run an upload test using the v1 / v MAC parameter
 */
func TestUploadValidV1(t *testing.T) {
	// Remove uploaded file after test
	defer cleanup()

	// Set config
	readConfig("config.toml")

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

/*
 * Run an upload test using the v2 MAC parameter
 */
func TestUploadValidV2(t *testing.T) {
	// Remove uploaded file after test
	defer cleanup()

	// Set config
	readConfig("config.toml")

	// Read catmetal file
	catMetalFile, err := os.ReadFile("catmetal.jpg")
	if err != nil {
		t.Fatal(err)
	}

	// Create request
	req, err := http.NewRequest("PUT", "/upload/thomas/abc/catmetal.jpg", bytes.NewBuffer(catMetalFile))
	q := req.URL.Query()
	q.Add("v2", "7318cd44d4c40731e3b2ff869f553ab2326eae631868e7b8054db20d4aee1c06")
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

/*
 * Run an upload test using the token MAC parameter
 */
func TestUploadValidMetronomeToken(t *testing.T) {
	// Remove uploaded file after test
	defer cleanup()

	// Set config
	readConfig("config.toml")

	// Read catmetal file
	catMetalFile, err := os.ReadFile("catmetal.jpg")
	if err != nil {
		t.Fatal(err)
	}

	// Create request
	req, err := http.NewRequest("PUT", "/upload/thomas/abc/catmetal.jpg", bytes.NewBuffer(catMetalFile))
	q := req.URL.Query()
	q.Add("token", "7318cd44d4c40731e3b2ff869f553ab2326eae631868e7b8054db20d4aee1c06")
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

/*
 * Run an upload test using no MAC parameter
 */
func TestUploadMissingMAC(t *testing.T) {
	// Remove uploaded file after test
	defer cleanup()

	// Set config
	readConfig("config.toml")

	// Read catmetal file
	catMetalFile, err := os.ReadFile("catmetal.jpg")
	if err != nil {
		t.Fatal(err)
	}

	// Create request
	req, err := http.NewRequest("PUT", "/upload/thomas/abc/catmetal.jpg", bytes.NewBuffer(catMetalFile))

	if err != nil {
		t.Fatal(err)
	package main

	/*
	 * Manual testing with CURL
	 * Send with:
	 * curl -X PUT "http://localhost:5050/upload/thomas/abc/catmetal.jpg?v=7b8879e2d1c733b423a70cde30cecc3a3c64a03f790d1b5bcbb2a6aca52b477e" --data-binary '@catmetal.jpg'
	 * HMAC: 7b8879e2d1c733b423a70cde30cecc3a3c64a03f790d1b5bcbb2a6aca52b477e
	 */

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
			log.Fatal(err)
		}
		defer from.Close()

		to, err := os.OpenFile(filepath.Join(conf.StoreDir, "thomas/abc/catmetal.jpg"), os.O_RDWR|os.O_CREATE, 0660)
		if err != nil {
			log.Fatal(err)
		}
		defer to.Close()

		_, err = io.Copy(to, from)
		if err != nil {
			log.Fatal(err)
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
				log.Println("Error while cleaning up:", err)
			}
		}
	}

	/*
	 * Test if reading the config file works
	 */
	func TestReadConfig(t *testing.T) {
		// Set config
		err := readConfig("config.toml")
		if err != nil {
			t.Fatal(err)
		}

		log.SetLevel(logrus.FatalLevel)
	}

	/*
	 * Run an upload test using the v1 / v MAC parameter
	 */
	func TestUploadValidV1(t *testing.T) {
		// Remove uploaded file after test
		defer cleanup()

		// Set config
		readConfig("config.toml")

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

	/*
	 * Run an upload test using the v2 MAC parameter
	 */
	func TestUploadValidV2(t *testing.T) {
		// Remove uploaded file after test
		defer cleanup()

		// Set config
		readConfig("config.toml")

		// Read catmetal file
		catMetalFile, err := os.ReadFile("catmetal.jpg")
		if err != nil {
			t.Fatal(err)
		}

		// Create request
		req, err := http.NewRequest("PUT", "/upload/thomas/abc/catmetal.jpg", bytes.NewBuffer(catMetalFile))
		q := req.URL.Query()
		q.Add("v2", "7318cd44d4c40731e3b2ff869f553ab2326eae631868e7b8054db20d4aee1c06")
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

	/*
	 * Run an upload test using the token MAC parameter
	 */
	func TestUploadValidMetronomeToken(t *testing.T) {
		// Remove uploaded file after test
		defer cleanup()

		// Set config
		readConfig("config.toml")

		// Read catmetal file
		catMetalFile, err := os.ReadFile("catmetal.jpg")
		if err != nil {
			t.Fatal(err)
		}

		// Create request
		req, err := http.NewRequest("PUT", "/upload/thomas/abc/catmetal.jpg", bytes.NewBuffer(catMetalFile))
		q := req.URL.Query()
		q.Add("token", "7318cd44d4c40731e3b2ff869f553ab2326eae631868e7b8054db20d4aee1c06")
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

	/*
	 * Run an upload test using no MAC parameter
	 */
	func TestUploadMissingMAC(t *testing.T) {
		// Remove uploaded file after test
		defer cleanup()

		// Set config
		readConfig("config.toml")

		// Read catmetal file
		catMetalFile, err := os.ReadFile("catmetal.jpg")
		if err != nil {
			t.Fatal(err)
		}

		// Create request
		req, err := http.NewRequest("PUT", "/upload/thomas/abc/catmetal.jpg", bytes.NewBuffer(catMetalFile))

		if err != nil {
			t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleRequest)

	// Send request and record response
	handler.ServeHTTP(rr, req)

	// Check status code
	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("handler returned wrong status code: got %v want %v. HTTP body: %s", status, http.StatusForbidden, rr.Body.String())
	}
}

/*
 * Run an upload test using an invalid MAC parameter
 */
func TestUploadInvalidMAC(t *testing.T) {
	// Remove uploaded file after test
	defer cleanup()

	// Set config
	readConfig("config.toml")

	// Read catmetal file
	catMetalFile, err := os.ReadFile("catmetal.jpg")
	if err != nil {
		t.Fatal(err)
	}

	// Create request
	req, err := http.NewRequest("PUT", "/upload/thomas/abc/catmetal.jpg", bytes.NewBuffer(catMetalFile))
		q := req.URL.Query()
		q.Add("v", "thisisinvalid")
		req.URL.RawQuery = q.Encode()

		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(handleRequest)

		// Send request and record response
		handler.ServeHTTP(rr, req)

		// Check status code
		if status := rr.Code; status != http.StatusForbidden {
			t.Errorf("handler returned wrong status code: got %v want %v. HTTP body: %s", status, http.StatusForbidden, rr.Body.String())
		}
	}

	/*
	 * Test upload using an invalid HTTP method (POST)
	 */
	func TestUploadInvalidMethod(t *testing.T) {
		// Remove uploaded file after test
		defer cleanup()

		// Set config
		readConfig("config.toml", &conf)

		// Read catmetal file
		catMetalFile, err := os.ReadFile("catmetal.jpg")
		if err != nil {
			t.Fatal(err)
		}

		// Create request
		req, err := http.NewRequest("POST", "/upload/thomas/abc/catmetal.jpg", bytes.NewBuffer(catMetalFile))

		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(handleRequest)

		// Send request and record response
		handler.ServeHTTP(rr, req)

		// Check status code
		if status := rr.Code; status != http.StatusMethodNotAllowed {
			t.Errorf("handler returned wrong status code: got %v want %v. HTTP body: %s", status, http.StatusMethodNotAllowed, rr.Body.String())
		}
	}

	/*
	 * Test if HEAD requests work
	 */
	func TestDownloadHead(t *testing.T) {
		// Set config
		readConfig("config.toml", &conf)

		// Mock upload
		mockUpload()
		defer cleanup()

		// Create request
		req, err := http.NewRequest("HEAD", "/upload/thomas/abc/catmetal.jpg", nil)

		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(handleRequest)

		// Send request and record response
		handler.ServeHTTP(rr, req)

		// Check status code
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v. HTTP body: %s", status, http.StatusOK, rr.Body.String())
		}
	}

	/*
	 * Test if GET download requests work
	 */
	func TestDownloadGet(t *testing.T) {
		// Set config
		readConfig("config.toml", &conf)

		// moch upload
		mockUpload()
		defer cleanup()

		// Create request
		req, err := http.NewRequest("GET", "/upload/thomas/abc/catmetal.jpg", nil)

		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(handleRequest)

		// Send request and record response
		handler.ServeHTTP(rr, req)

		// Check status code
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v. HTTP body: %s", status, http.StatusOK, rr.Body.String())
		}
	}

	/*
	 * Test if asking for an empty file name works
	 */
	func TestEmptyGet(t *testing.T) {
		// Set config
		readConfig("config.toml", &conf)

		// Create request
		req, err := http.NewRequest("GET", "", nil)

		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(handleRequest)

		// Send request and record response
		handler.ServeHTTP(rr, req)

		// Check status code
		if status := rr.Code; status != http.StatusForbidden {
			t.Errorf("handler returned wrong status code: got %v want %v. HTTP body: %s", status, http.StatusForbidden, rr.Body.String())
		}
	}

	/*
	 * Check if access to subdirectory is forbidden.
	 * PASS if access is blocked with HTTP "Forbidden" response.
	 * FAIL if there is any other response or even a directory listing exposed.
	 * Introduced to check issue #14 (resolved in 7dff0209)
	 */
	func TestDirListing(t *testing.T) {
		// Set config
		readConfig("config.toml", &conf)

		mockUpload()
		defer cleanup()

		// Create request
		req, err := http.NewRequest("GET", "/upload/thomas/", nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(handleRequest)

		// Send request and record response
		handler.ServeHTTP(rr, req)

		// Check status code
		if status := rr.Code; status != http.StatusForbidden {
			t.Errorf("handler returned wrong status code: got %v want %v. HTTP body: %s", status, http.StatusForbidden, rr.Body.String())
		}
	}

	/*
	 * Test if the server handles large file uploads correctly
	 */
	func TestUploadLargeFile(t *testing.T) {
		// Remove uploaded file after test
		defer cleanup()

		// Set config
		readConfig("config.toml")

		// Create a large file for testing
		largeFile := make([]byte, 10*1024*1024) // 10 MB
		for i := range largeFile {
			largeFile[i] = 'a'
		}

		// Create request
		req, err := http.NewRequest("PUT", "/upload/thomas/abc/largefile.txt", bytes.NewBuffer(largeFile))
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

	/*
	 * Test if the server handles concurrent uploads correctly
	 */
	func TestConcurrentUploads(t *testing.T) {
		// Remove uploaded files after test
		defer cleanup()

		// Set config
		readConfig("config.toml")

		// Read catmetal file
		catMetalFile, err := os.ReadFile("catmetal.jpg")
		if err != nil {
			t.Fatal(err)
		}

		// Create a wait group to wait for all goroutines to finish
		var wg sync.WaitGroup

		// Function to perform an upload
		uploadFunc := func(filename string) {
			defer wg.Done()

			// Create request
			req, err := http.NewRequest("PUT", filename, bytes.NewBuffer(catMetalFile))
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

		// Perform concurrent uploads
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go uploadFunc(fmt.Sprintf("/upload/thomas/abc/catmetal_%d.jpg", i))
		}

		// Wait for all uploads to finish
		wg.Wait()
	}
	q := req.URL.Query()
	q.Add("v", "thisisinvalid")
	req.URL.RawQuery = q.Encode()

	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleRequest)

	// Send request and record response
	handler.ServeHTTP(rr, req)

	// Check status code
	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("handler returned wrong status code: got %v want %v. HTTP body: %s", status, http.StatusForbidden, rr.Body.String())
	}
}

/*
 * Test upload using an invalid HTTP method (POST)
 */
func TestUploadInvalidMethod(t *testing.T) {
	// Remove uploaded file after test
	defer cleanup()

	// Set config
	readConfig("config.toml", &conf)

	// Read catmetal file
	catMetalFile, err := os.ReadFile("catmetal.jpg")
	if err != nil {
		t.Fatal(err)
	}

	// Create request
	req, err := http.NewRequest("POST", "/upload/thomas/abc/catmetal.jpg", bytes.NewBuffer(catMetalFile))

	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleRequest)

	// Send request and record response
	handler.ServeHTTP(rr, req)

	// Check status code
	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("handler returned wrong status code: got %v want %v. HTTP body: %s", status, http.StatusMethodNotAllowed, rr.Body.String())
	}
}

/*
 * Test if HEAD requests work
 */
func TestDownloadHead(t *testing.T) {
	// Set config
	readConfig("config.toml", &conf)

	// Mock upload
	mockUpload()
	defer cleanup()

	// Create request
	req, err := http.NewRequest("HEAD", "/upload/thomas/abc/catmetal.jpg", nil)

	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleRequest)

	// Send request and record response
	handler.ServeHTTP(rr, req)

	// Check status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v. HTTP body: %s", status, http.StatusOK, rr.Body.String())
	}
}

/*
 * Test if GET download requests work
 */
func TestDownloadGet(t *testing.T) {
	// Set config
	readConfig("config.toml", &conf)

	// moch upload
	mockUpload()
	defer cleanup()

	// Create request
	req, err := http.NewRequest("GET", "/upload/thomas/abc/catmetal.jpg", nil)

	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleRequest)

	// Send request and record response
	handler.ServeHTTP(rr, req)

	// Check status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v. HTTP body: %s", status, http.StatusOK, rr.Body.String())
	}
}

/*
 * Test if asking for an empty file name works
 */
func TestEmptyGet(t *testing.T) {
	// Set config
	readConfig("config.toml", &conf)

	// Create request
	req, err := http.NewRequest("GET", "", nil)

	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleRequest)

	// Send request and record response
	handler.ServeHTTP(rr, req)

	// Check status code
	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("handler returned wrong status code: got %v want %v. HTTP body: %s", status, http.StatusForbidden, rr.Body.String())
	}
}

/*
 * Check if access to subdirectory is forbidden.
 * PASS if access is blocked with HTTP "Forbidden" response.
 * FAIL if there is any other response or even a directory listing exposed.
 * Introduced to check issue #14 (resolved in 7dff0209)
 */
func TestDirListing(t *testing.T) {
	// Set config
	readConfig("config.toml", &conf)

	mockUpload()
	defer cleanup()

	// Create request
	req, err := http.NewRequest("GET", "/upload/thomas/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleRequest)

	// Send request and record response
	handler.ServeHTTP(rr, req)

	// Check status code
	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("handler returned wrong status code: got %v want %v. HTTP body: %s", status, http.StatusForbidden, rr.Body.String())
	}
}
/*
 * Test if the server handles large file uploads correctly
 */
func TestUploadLargeFile(t *testing.T) {
    // Remove uploaded file after test
    defer cleanup()

    // Set config
    readConfig("config.toml")

    // Create a large file for testing
    largeFile := make([]byte, 10*1024*1024) // 10 MB
    for i := range largeFile {
        largeFile[i] = 'a'
    }

    // Create request
    req, err := http.NewRequest("PUT", "/upload/thomas/abc/largefile.txt", bytes.NewBuffer(largeFile))
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

/*
 * Test if the server handles concurrent uploads correctly
 */
func TestConcurrentUploads(t *testing.T) {
    // Remove uploaded files after test
    defer cleanup()

    // Set config
    readConfig("config.toml")

    // Read catmetal file
    catMetalFile, err := os.ReadFile("catmetal.jpg")
    if err != nil {
        t.Fatal(err)
    }

    // Create a wait group to wait for all goroutines to finish
    var wg sync.WaitGroup

    // Function to perform an upload
    uploadFunc := func(filename string) {
        defer wg.Done()

        // Create request
        req, err := http.NewRequest("PUT", filename, bytes.NewBuffer(catMetalFile))
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

    // Perform concurrent uploads
    for i := 0; i < 5; i++ {
        wg.Add(1)
        go uploadFunc(fmt.Sprintf("/upload/thomas/abc/catmetal_%d.jpg", i))
    }

    // Wait for all uploads to finish
    wg.Wait()
}