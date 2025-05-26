package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/feature/cloudfront/sign"
)

var (
	resourcePath      string
	cfSigner          *sign.CookieSigner
	expiresInDuration time.Duration
)

func init() {
	// Load environment variables
	cfDomain := os.Getenv("CF_DOMAIN")
	cfKeyPairId := os.Getenv("CF_KEY_PAIR_ID")
	encodedKey := os.Getenv("CF_PRIVATE_KEY")
	if cfDomain == "" || cfKeyPairId == "" || encodedKey == "" {
		log.Fatal("Missing environment variables")
	}

	// Decode base64
	decodedKey, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		log.Fatalf("Failed to base64 decode CF_PRIVATE_KEY: %v", err)
	}

	// Parse PEM
	block, _ := pem.Decode(decodedKey)
	if block == nil {
		log.Fatal("Failed to parse PEM block from decoded private key")
	}

	// Parse RSA key
	parsedKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse RSA private key: %v", err)
	}

	// Create signer
	cfSigner = sign.NewCookieSigner(cfKeyPairId, parsedKey)

	// Set resource path and expiration
	resourcePath = cfDomain + "/recipes*"
	expiresInDuration = 1 * time.Hour

	log.Printf(
		"Lambda cold start. CF_DOMAIN=%s, CF_KEY_PAIR_ID=%s, PrivateKeyPrefix=%s",
		cfDomain,
		cfKeyPairId,
		string(decodedKey[:3]),
	)
}

func main() {
	lambda.Start(handler)
}
