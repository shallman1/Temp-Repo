package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

type HmacSignatureGenerator struct {
	APIUsername string
	APIKey      string
}

func (h *HmacSignatureGenerator) createISO8601Timestamp() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05Z")
}

func (h *HmacSignatureGenerator) generateSignature(uri string) (string, string) {
	timestamp := h.createISO8601Timestamp()
	params := fmt.Sprintf("%s%s%s", h.APIUsername, timestamp, uri)
	hmac := hmac.New(sha256.New, []byte(h.APIKey))
	hmac.Write([]byte(params))
	signature := hex.EncodeToString(hmac.Sum(nil))
	return signature, timestamp
}

func getDomainInfo(domain, apiUsername, apiKey string) (string, error) {
	uri := "/v1/iris-enrich/"
	generator := HmacSignatureGenerator{APIUsername: apiUsername, APIKey: apiKey}
	signature, timestamp := generator.generateSignature(uri)

	params := url.Values{}
	params.Add("api_username", apiUsername)
	params.Add("timestamp", timestamp)
	params.Add("signature", signature)
	params.Add("domain", domain)

	apiURL := fmt.Sprintf("https://api.domaintools.com%s?%s", uri, params.Encode())
	resp, err := http.Get(apiURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP error: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func main() {
	domain := "google.com"
	apiUsername := "api_user_here"
	apiKey := "api_key_here"

	domainInfo, err := getDomainInfo(domain, apiUsername, apiKey)
	if err != nil {
		fmt.Printf("Error occurred: %s\n", err)
		return
	}

	fmt.Println(domainInfo)
