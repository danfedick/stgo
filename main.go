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

	var data stigData
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

	findings := data.Stig.Findings

	if *srgFlag != "" || *vulnFlag != "" {
		matchingFindings := 0
		for _, finding := range findings {
			if (finding.Version == *srgFlag && *srgFlag != "") || (finding.Id == *vulnFlag && *vulnFlag != "") {
				matchingFindings++
				fmt.Println("")
				fmt.Println("\033[4;36mVULN ID:\033[0m")
				fmt.Println(finding.Id)
				fmt.Println("")
				fmt.Println("\033[4;36mSRG:\033[0m")
				fmt.Println(finding.Version)
				fmt.Println("")
				fmt.Println("\033[4;36mSEVERITY:\033[0m")

				severity := finding.Severity
				switch severity {
				case "high":
					fmt.Print("\033[31m") // Red
				case "medium":
					fmt.Print("\033[33m") // Orange
				case "low":
					fmt.Print("\033[32m") // Green
				}
				fmt.Println("")
				fmt.Println(severity)
				fmt.Print("\033[0m") // Reset color
				fmt.Println("")
				fmt.Println("\033[4;36mTITLE:\033[0m")
				fmt.Println(finding.Title)
				fmt.Println("")
				fmt.Println("\033[4;36mDESCRIPTION:\033[0m")
				fmt.Println(finding.Description)
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
			findingMap := finding
			fmt.Println(findingMap.Id)
		}
	}
}

func readStigFromFile(file string) (stigData, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return stigData{}, err
	}
	var result stigData
	err = json.Unmarshal(data, &result)
	if err != nil {
		return stigData{}, err
	}
	return result, nil
}

func readStigFromURL(url string) (stigData, error) {
	resp, err := http.Get(url)
	if err != nil {
		return stigData{}, err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return stigData{}, err
	}
	var result stigData
	err = json.Unmarshal(data, &result)
	if err != nil {
		return stigData{}, err
	}
	return result, nil
}
