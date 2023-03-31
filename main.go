package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	fileFlag := flag.String("file", "", "Path to local JSON file")
	urlFlag := flag.String("url", "", "URL to fetch the JSON data")
	srgFlag := flag.String("srg", "", "STIG version to search for")
	vulnFlag := flag.String("vuln", "", "The vulnerability ID to search for")

	flag.Parse()

	if *fileFlag == "" && *urlFlag == "" {
		fmt.Println("Error: Neither file nor URL provided")
		flag.PrintDefaults()
		return
	}

	var data map[string]interface{}
	var err error

	if *fileFlag != "" {
		data, err = readStigFromFile(*fileFlag)
	} else {
		data, err = readStigFromURL(*urlFlag)
	}

	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	findings := data["stig"].(map[string]interface{})["findings"].(map[string]interface{})

	if *srgFlag != "" || *vulnFlag != "" {
		matchingFindings := 0
		for _, finding := range findings {
			findingMap := finding.(map[string]interface{})
			if (findingMap["version"].(string) == *srgFlag && *srgFlag != "") || (findingMap["id"].(string) == *vulnFlag && *vulnFlag != "") {
				matchingFindings++
				fmt.Println("\033[4;36mVULN ID:\033[0m")
				fmt.Println(findingMap["id"].(string))
				fmt.Println("\033[4;36mSRG:\033[0m")
				fmt.Println(findingMap["version"].(string))
				fmt.Println("\033[4;36mSEVERITY:\033[0m")
				fmt.Println(findingMap["severity"].(string))
				fmt.Println("\033[4;36mTITLE:\033[0m")
				fmt.Println(findingMap["title"].(string))
				fmt.Println("\033[4;36mDESCRIPTION:\033[0m")
				fmt.Println(findingMap["description"].(string))
				fmt.Println("")
			}
		}

		if matchingFindings == 0 {
			if *srgFlag != "" {
				fmt.Printf("No findings with version '%s' found.\n", *srgFlag)
			}
			if *vulnFlag != "" {
				fmt.Printf("No findings with vulnerability ID '%s' found.\n", *vulnFlag)
			}
		}
	} else {
		fmt.Println("List of IDs:")
		for _, finding := range findings {
			findingMap := finding.(map[string]interface{})
			fmt.Println(findingMap["id"].(string))
		}
	}
}

func readStigFromFile(file string) (map[string]interface{}, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func readStigFromURL(url string) (map[string]interface{}, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}
