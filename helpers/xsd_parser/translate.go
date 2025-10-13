package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// Translation one text translation from Yandex.
type Translation struct {
	Text                 string `json:"text"`
	DetectedLanguageCode string `json:"detectedLanguageCode"`
}

// Response Yandex.Translate response.
type Response struct {
	Translations []Translation `json:"translations"`
}

func translate(folderID string, apiKey string, texts []string) ([]string, error) {
	data := map[string]interface{}{
		"folderId":           folderID,
		"texts":              texts,
		"targetLanguageCode": "en",
	}
	jsonData, err := json.Marshal(data)

	if err != nil {
		panic(err)
	}

	bodyReader := bytes.NewBuffer(jsonData)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(maxTimeOutSec)*time.Second)
	defer cancel()

	// client := &http.Client{}

	client := &http.Client{Transport: nil, CheckRedirect: nil, Jar: nil,
		Timeout: time.Duration(maxTimeOutSec) * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bodyReader)

	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Api-Key "+apiKey)
	resp, err := client.Do(req)

	if err != nil {
		panic(err)
	}

	defer func() {
		errClose := resp.Body.Close()
		if errClose != nil {
			log.Println(err)
		}
	}()

	log.Printf("HTTP Status Code: %d\n", resp.StatusCode)

	var response Response

	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		log.Printf("rror decoding response: %v\n", err)

		return nil, fmt.Errorf("decode response error: %w", err)
	}

	engValues := make([]string, len(response.Translations))
	for i := range len(response.Translations) {
		engValues[i] = response.Translations[i].Text
	}

	return engValues, nil
}
