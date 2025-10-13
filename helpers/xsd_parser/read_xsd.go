package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"slices"
	"strings"
)

// CreateRusMap Create a map ["tag" => "Russian explanation"].
func CreateRusMap(xsdPath string) (map[string]string, error) {
	data, err := os.ReadFile(xsdPath) //nolint
	if err != nil {
		log.Fatal(err)
	}

	tokenMap := make(map[string]string)

	var keyFound = false

	var annotFound = false

	var docFound = false

	var key string

	var docValue string

	decoder := xml.NewDecoder(bytes.NewReader(data))

	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break // End of XML document
		}

		if err != nil {
			log.Printf("Error decoding XML:%s\n", err.Error())

			return nil, fmt.Errorf("decode XML error:%w", err)
		}

		switch tokenVal := token.(type) {
		case xml.StartElement:
			// elemnent
			if tokenVal.Name.Local == "element" || tokenVal.Name.Local == "attribute" {
				ind := slices.IndexFunc(tokenVal.Attr, func(attr xml.Attr) bool { return attr.Name.Local == "name" })
				if ind >= 0 {
					key = tokenVal.Attr[ind].Value
					keyFound = true
					annotFound = false
				}
			}
			// annotation
			if tokenVal.Name.Local == "annotation" && keyFound {
				annotFound = true
			}
			// documentation
			if tokenVal.Name.Local == "documentation" && keyFound && annotFound {
				docFound = true
			}
		// case xml.EndElement:
		// 	fmt.Printf("End Element: %s\n", t.Name.Local)
		case xml.CharData:
			content := strings.TrimSpace(string(tokenVal))
			if content != "" && keyFound && annotFound && docFound {
				docValue = content
			}
		}

		if keyFound && annotFound && key != "" && docValue != "" {
			tokenMap[key] = docValue
			keyFound = false
			annotFound = false
			docFound = false
			key = ""
			docValue = ""
		}
	}

	return tokenMap, nil
}
