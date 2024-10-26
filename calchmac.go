package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "os"
)

func main() {
    secret := "supa-secret-maria-und-josef" // Replace this with the exact secret used
    content, _ := os.ReadFile("hmac.jpg")

    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(content)
    expectedMAC := hex.EncodeToString(mac.Sum(nil))

    fmt.Println("Expected HMAC:", expectedMAC)
}
