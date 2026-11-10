package audit

import (
	"slices"
	"strings"
	"testing"
)

func TestRulesCarryTrustWitness(t *testing.T) {
	a := parseTest(t, "a.yml", "on: pull_request_target\npermissions: {}\njobs: {call: {uses: ./.github/workflows/b.yml, secrets: inherit}}")
	b := parseTest(t, "b.yml", "on: workflow_call\npermissions: {contents: write}\njobs:\n  test:\n"+
		"    runs-on: {group: build, labels: [linux, self-hosted]}\n    steps:\n"+
		"      - uses: actions/checkout@"+strings.Repeat("a", 40)+"\n        with:\n          ref: '${{ github.event.pull_request.head.sha }}'\n"+
		"      - run: 'echo ${{ github.event.pull_request.title }}'\n")
	graph, _, _ := buildGraph([]Workflow{b, a})
	findings := securityFindings(graph)
	want := map[string]int{"WF001": 1, "WF003": 1, "WF004": 1, "WF006": 1, "WF007": 1, "WF011": 1}
	for _, finding := range findings {
		want[finding.Rule]--
		if finding.Path == b.Path && !slices.Equal(finding.Via, []string{a.Path, b.Path}) {
			t.Errorf("wrong witness: %+v", finding)
		}
	}
	for rule, remaining := range want {
		if remaining != 0 {
			t.Errorf("wrong number of %s findings: %+v", rule, findings)
		}
	}
}

func TestSafePrJob(t *testing.T) {
	workflow := parseTest(t, "safe.yml", "on: pull_request\npermissions: {contents: read}\njobs:\n"+
		"  test:\n    runs-on: ubuntu-latest\n    steps:\n"+
		"      - uses: actions/checkout@"+strings.Repeat("a", 40)+"\n        with: {persist-credentials: false}\n"+
		"      - run: 'printf %s \"$TITLE\"'\n        env:\n          TITLE: '${{ github.event.pull_request.title }}'\n")
	graph, _, findings := buildGraph([]Workflow{workflow})
	findings = append(findings, securityFindings(graph)...)
	if len(findings) != 0 {
		t.Fatalf("safe workflow findings: %+v", findings)
	}
}
