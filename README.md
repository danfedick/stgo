# STIG Viewer

This is a simple command-line tool to read and search through JSON data containing Security Technical Implementation Guide (STIG) information. It allows users to list all the IDs within the provided STIG data and search for findings with a specific STIG version. The program can read data from a local file or fetch data from a remote URL.

This application was designed for the [Application STIG](https://www.stigviewer.com/stig/application_security_requirements_guide/2011-12-28/MAC-3_Sensitive/json). For more information about STIGs, visit the [STIG Viewer website](https://www.stigviewer.com/).

## Demo

You can watch a demo of the program in action here:
[![asciicast](https://asciinema.org/a/XE996IdHwrNHKta63yD0ykInA.svg)](https://asciinema.org/a/XE996IdHwrNHKta63yD0ykInA)

## Installation

1. Make sure you have [Go](https://golang.org/) installed on your system.
2. Clone this repository to your local machine.
3. Navigate to the project directory and build the binary:

```bash
cd stig-viewer
go build -o stgo ./main.go
```

## Usage

### Listing Vulnerability IDs

To list all Vulnerability IDs within the provided STIG data, use the `-file` flag for a local file or the `-url` flag for a remote URL:

```bash
./stgo -file stig.json 
```

Or:

```bash
./stgo -url https://www.example.com/stig.json 
```

## Searching for a Specific SRG Version

To search for findings with a specific STIG version, use the -srg flag along with -file or -url:

```bash
./stgo -file ./stigs/example_app_stig.json -srg SRG-APP-000074
```

Or:

```bash
./stgo -url https://www.example.com/stig.json -srg SRG-APP-000074
```

### License

This project is licensed under the MIT License. See the LICENSE file for details.
