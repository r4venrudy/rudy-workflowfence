package main

import (
	"net/url"

	"github.com/r4venrudy/rudy-workflowfence/internal/audit"
)

type object = map[string]any

var ruleNames = []string{
	"Direct context interpolation",
	"Mutable dependency reference",
	"Broad or privileged write permission",
	"Privileged checkout of external code",
	"Inherited repository token defaults",
	"External event on a self-hosted runner",
	"Persisted checkout credentials",
	"Unresolved local workflow",
	"Unclassified dependency",
	"Local reusable workflow cycle",
	"Inherited secrets",
	"Unrecognized permission declaration",
}

func sarif(report audit.Report) object {
	results := make([]object, 0, len(report.Findings))
	for _, finding := range report.Findings {
		level := "warning"
		if finding.Severity == "high" {
			level = "error"
		}
		location := url.URL{Path: finding.Path}
		properties := object{}
		if len(finding.Via) != 0 {
			properties["trustPath"] = finding.Via
		}
		results = append(results, object{
			"ruleId":  finding.Rule,
			"level":   level,
			"message": object{"text": finding.Message},
			"locations": []object{{"physicalLocation": object{
				"artifactLocation": object{"uri": location.EscapedPath()},
				"region":           object{"startLine": finding.Line},
			}}},
			"properties": properties,
		})
	}
	rules := make([]object, 0, len(ruleNames))
	for index, name := range ruleNames {
		rule := []byte{'W', 'F', '0', byte('0' + (index+1)/10), byte('0' + (index+1)%10)}
		rules = append(rules, object{"id": string(rule), "shortDescription": object{"text": name}})
	}
	return object{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []object{{
			"tool": object{"driver": object{
				"name": "Rudy WorkflowFence", "version": version, "rules": rules,
				"informationUri": "https://github.com/r4venrudy/rudy-workflowfence",
			}},
			"results": results,
		}},
	}
}
