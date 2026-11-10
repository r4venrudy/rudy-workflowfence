package audit

import (
	"strings"
	"testing"
)

func TestParseRejectsAmbiguity(t *testing.T) {
	for _, src := range []string{
		"on: push\non: pull_request\njobs: {a: {}}",
		"on: push\njobs: {a: {steps: [{run: test, run: build}]}}",
		"on: &trigger push\njobs: {a: {}}",
		"on: push\njobs: {a: {}}\n---\non: push",
		"on: [push, 42]\njobs: {a: {}}",
		"on: push\njobs: {a: {steps: [oops]}}",
	} {
		if _, err := Parse("test.yml", []byte(src)); err == nil {
			t.Errorf("accepted ambiguous input %q", src)
		}
	}
	for _, trigger := range []string{"push", "[push, pull_request]", "{push: {}, pull_request: {}}"} {
		if _, err := Parse("test.yml", []byte("on: "+trigger+"\njobs: {a: {steps: [{run: make}]}}")); err != nil {
			t.Errorf("rejected trigger %q: %v", trigger, err)
		}
	}
}

func TestParseLimits(t *testing.T) {
	if _, err := Parse("oversized.yml", []byte(strings.Repeat("a", maxBytes+1))); err == nil {
		t.Fatal("oversized workflow accepted")
	}
	deep := "on: push\njobs: {a: {steps: [{run: make, env: {deep: " +
		strings.Repeat("[", maxDepth+1) + "x" + strings.Repeat("]", maxDepth+1) + "}}]}}"
	if _, err := Parse("deep.yml", []byte(deep)); err == nil {
		t.Fatal("deep workflow accepted")
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte("on: push\njobs: {test: {steps: [{run: make}]}}"))
	f.Add([]byte("on: [pull_request, workflow_call]\njobs: {test: {uses: ./.github/workflows/local.yml}}"))
	f.Fuzz(func(t *testing.T, content []byte) { _, _ = Parse("fuzz.yml", content) })
}
