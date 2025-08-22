// parse the XSD MRPA scheme an translate with Yandex.Translate
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
)

const apiURL string = "https://translate.api.cloud.yandex.net/translate/v2/translate"

const cppHeaders string = `#include <array>
#include <string_view>
`
const cppArrTempl string = "constexpr std::array<std::string_view,%d> %s{"
const defaultXsdPath string = "/home/oleg/dev/eSign/csp_pdf/test_files/mrpa/valid/ON_EMCHD_1_928_00_01_01_01.xsd"
const defaultSavePath string = "/home/oleg/mrpa_strings_translations.cpp"
const maxTimeOutSec int = 10

func writeOneArr(file *os.File, name string, vals []string) error {
	_, err := fmt.Fprintf(file, cppArrTempl, len(vals), name)
	if err != nil {
		return fmt.Errorf("write one array error: %w", err)
	}

	for _, val := range vals {
		_, err = file.WriteString("\"")

		if err != nil {
			return fmt.Errorf("write one array error: %w", err)
		}

		_, err = file.WriteString(val)

		if err != nil {
			return fmt.Errorf("write one array error: %w", err)
		}

		_, err = file.WriteString("\",")

		if err != nil {
			return fmt.Errorf("write one array error: %w", err)
		}
	}

	_, err = file.WriteString("};\n")

	if err != nil {
		return fmt.Errorf("write one array error: %w", err)
	}

	return nil
}

func main() {

	// parse arguments
	folderID := flag.String("folder", "", "folder id")
	apiKey := flag.String("api", "", "api key")
	xsdPath := flag.String("xsd_path", defaultXsdPath, "path to the .xsd file")
	outputFile := flag.String("o", defaultSavePath, "path to output file")
	flag.Parse()

	if *folderID == "" || *apiKey == "" {
		log.Fatal("You need to pass two args: --folder=folder_id --api=api_key")
	}

	// read the file
	tokenMap, err := CreateRusMap(*xsdPath)
	if err != nil {
		log.Fatal(err)
	}

	// create a sorted keys array
	keys := make([]string, 0, len(tokenMap))
	for k := range tokenMap {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	// Create values array in the same order
	rusValues := make([]string, len(keys))
	for i, key := range keys {
		rusValues[i] = tokenMap[key]
	}

	// translate
	engValues, err := translate(*folderID, *apiKey, rusValues)
	if err != nil {
		log.Fatal(err)
	}

	// create a .cpp file
	file, err := os.Create(*outputFile)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		closeErr := file.Close()
		if closeErr != nil {
			log.Printf("Close file error %t", err)
		}
	}()
	// write includes
	_, err = file.WriteString(cppHeaders)
	if err != nil {
		log.Println(err)
	}
	// tag_names
	err = writeOneArr(file, "tag_names", keys)
	if err != nil {
		log.Println(err)
	}
	// rus_expl
	err = writeOneArr(file, "rus_expl", rusValues)
	if err != nil {
		log.Println(err)
	}
	// eng_expl
	err = writeOneArr(file, "eng_expl", engValues)
	if err != nil {
		log.Println(err)
	}
}
