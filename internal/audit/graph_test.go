package audit

import (
	"slices"
	"strings"
	"testing"
)

func TestLocalGraph(t *testing.T) {
	a := parseTest(t, "a.yml", "on: pull_request_target\njobs: {relay: {uses: ./.github/workflows/b.yml}}")
	b := parseTest(t, "b.yml", "on: workflow_call\njobs: {relay: {uses: ./.github/workflows/c.yml}}")
	c := parseTest(t, "c.yml", "on: workflow_call\njobs: {loop: {uses: ./.github/workflows/b.yml}, gone: {uses: ./.github/workflows/missing.yml}}")
	graph, deps, findings := buildGraph([]Workflow{c, a, b})
	want := []string{a.Path, b.Path, c.Path}
	if got := graph.witnesses(privileged)[2]; !slices.Equal(got, want) {
		t.Fatalf("witness %v, want %v", got, want)
	}
	if len(deps) != 4 || len(findings) != 2 || findings[0].Rule != "WF008" || findings[1].Rule != "WF010" {
		t.Fatalf("deps=%+v findings=%+v", deps, findings)
	}
}

func TestDependencyPins(t *testing.T) {
	hash := strings.Repeat("a", 40)
	image := strings.Repeat("b", 64)
	workflow := parseTest(t, "pin.yml", "on: push\njobs:\n  job:\n    steps:\n"+
		"    - uses: actions/checkout@"+hash+"\n"+
		"    - uses: actions/checkout@v7\n"+
		"    - uses: docker://image@sha256:"+image+"\n"+
		"    - uses: ./custom\n")
	_, deps, findings := buildGraph([]Workflow{workflow})
	if len(deps) != 4 || !deps[0].Immutable || deps[1].Immutable || !deps[2].Immutable ||
		deps[3].Kind != "local-action" || len(findings) != 1 || findings[0].Rule != "WF002" {
		t.Fatalf("deps=%+v findings=%+v", deps, findings)
	}
}
