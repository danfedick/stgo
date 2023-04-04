package main

type stigData struct {
	Stig struct {
		Findings map[string]stigFindings `json:"findings"`
	} `json:"stig"`
}

type stigFindings struct {
	CheckId     string      `json:"checkid"`
	CheckText   string      `json:"checktext"`
	Description string      `json:"description"`
	FixId       string      `json:"fixid"`
	FixText     string      `json:"fixtext"`
	IaControls  interface{} `json:"iacontrols"`
	Id          string      `json:"id"`
	RuleID      string      `json:"ruleID"`
	Severity    string      `json:"severity"`
	Title       string      `json:"title"`
	Version     string      `json:"version"`
}
