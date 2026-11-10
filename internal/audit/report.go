package audit

import (
	"cmp"
	"slices"
	"strings"
)

type Report struct {
	SchemaVersion int          `json:"schemaVersion"`
	Workflows     int          `json:"workflows"`
	Dependencies  []Dependency `json:"dependencies"`
	Findings      []Finding    `json:"findings"`
}

func Analyze(workflows []Workflow) Report {
	graph, dependencies, findings := buildGraph(workflows)
	findings = append(findings, securityFindings(graph)...)
	slices.SortFunc(findings, func(a, b Finding) int {
		return cmp.Or(strings.Compare(a.Path, b.Path), cmp.Compare(a.Line, b.Line),
			strings.Compare(a.Rule, b.Rule), strings.Compare(a.Job, b.Job),
			strings.Compare(a.Message, b.Message))
	})
	return Report{SchemaVersion: 1, Workflows: len(workflows), Dependencies: dependencies, Findings: findings}
}

func (report Report) Blocks(threshold string) bool {
	for _, finding := range report.Findings {
		if threshold == "medium" || (threshold == "high" && finding.Severity == "high") {
			return true
		}
	}
	return false
}
