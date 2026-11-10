package audit

import (
	"slices"
	"testing"
)

func parseTest(t *testing.T, name, source string) Workflow {
	t.Helper()
	workflow, err := Parse(".github/workflows/"+name, []byte(source))
	if err != nil {
		t.Fatal(err)
	}
	return workflow
}

func TestEventAndPermissions(t *testing.T) {
	workflow := parseTest(t, "w.yml", "on: [push, pull_request_target]\npermissions: {issues: write, contents: write}\njobs: {inherit: {}, clear: {permissions: {}}, scoped: {permissions: {id-token: write}}}")
	if got := eventTrust(events(workflow)); got != external|privileged {
		t.Fatalf("trust bits %b", got)
	}
	want := [][]string{{"contents", "issues"}, nil, {"id-token"}}
	for index, job := range jobs(workflow) {
		result := jobPermissions(workflow, job.node)
		if !result.declared || !result.valid || !slices.Equal(result.write, want[index]) {
			t.Errorf("job %s: %+v", job.name, result)
		}
	}
	if eventTrust([]string{"push", "workflow_call"}) != 0 || eventTrust([]string{"pull_request"}) != external {
		t.Fatal("unprivileged events classified incorrectly")
	}
}
