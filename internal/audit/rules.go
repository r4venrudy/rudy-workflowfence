package audit

import (
	"strings"

	"go.yaml.in/yaml/v3"
)

func securityFindings(graph graph) []Finding {
	low := graph.witnesses(external)
	high := graph.witnesses(privileged)
	findings := []Finding{}
	for index, workflow := range graph.nodes {
		add := func(rule, severity string, line int, job, message string, via []string) {
			findings = append(findings, workflow.finding(rule, severity, line, job, message, via))
		}
		workflowPermissions := lookup(workflow.root, "permissions")
		inherited := permissionSet(workflowPermissions)
		if inherited.all {
			add("WF003", "high", workflowPermissions.Line, "", "Replace workflow-wide write-all with minimal job permissions.", nil)
		}
		if inherited.declared && !inherited.valid {
			add("WF012", "high", workflowPermissions.Line, "", "Declare permissions as read-all, write-all, or a static permission map.", nil)
		}
		missing := false
		for _, job := range jobs(workflow) {
			p := jobPermissions(workflow, job.node)
			own := lookup(job.node, "permissions")
			missing = missing || !p.declared
			if own != nil && !p.valid {
				add("WF012", "high", own.Line, job.name, "Declare job permissions using a static permission map or shorthand.", nil)
			}
			if p.canWrite() && high[index] != nil {
				add("WF003", "high", job.node.Line, job.name,
					"Externally influenced privileged job declares write scopes ("+p.description()+"). Review and isolate write access.", high[index])
			} else if own != nil && p.all {
				add("WF003", "high", own.Line, job.name, "Replace job write-all with explicit scopes.", nil)
			}
			if low[index] != nil && selfHosted(lookup(job.node, "runs-on")) {
				add("WF006", "high", lookup(job.node, "runs-on").Line, job.name,
					"An externally influenced workflow can reach an explicitly self-hosted runner.", low[index])
			}
			if secrets := lookup(job.node, "secrets"); low[index] != nil && isString(secrets) && secrets.Value == "inherit" {
				add("WF011", "high", secrets.Line, job.name,
					"Pass required secrets by name instead of inheriting every available secret.", low[index])
			}
			for _, step := range steps(job.node) {
				run := lookup(step, "run")
				if isString(run) && expressionSource(run.Value, textSources) {
					add("WF001", "high", run.Line, job.name,
						"An externally influenced GitHub context is inserted into shell source. Pass it as data through an environment variable.", low[index])
				}
				checkout := lookup(step, "uses")
				if !isCheckout(checkout) {
					continue
				}
				with := lookup(step, "with")
				for _, name := range []string{"ref", "repository"} {
					value := lookup(with, name)
					if high[index] != nil && isString(value) && expressionSource(value.Value, checkoutSources) {
						add("WF004", "high", value.Line, job.name,
							"Privileged checkout explicitly selects externally influenced code. Use a trusted revision or isolate the unprivileged build.", high[index])
					}
				}
				persist := lookup(with, "persist-credentials")
				if (low[index] != nil || p.canWrite()) && (persist == nil || !strings.EqualFold(persist.Value, "false")) {
					add("WF007", "medium", checkout.Line, job.name,
						"Disable checkout credential persistence unless a later Git operation requires it.", low[index])
				}
			}
		}
		if missing {
			add("WF005", "medium", lookup(workflow.root, "jobs").Line, "",
				"At least one job inherits repository-default token permissions. Set an explicit workflow default.", nil)
		}
	}
	return findings
}

func selfHosted(runner *yaml.Node) bool {
	if runner == nil {
		return false
	}
	if runner.Kind == yaml.MappingNode {
		runner = lookup(runner, "labels")
		if runner == nil {
			return false
		}
	}
	if isString(runner) {
		return strings.EqualFold(runner.Value, "self-hosted")
	}
	if runner.Kind == yaml.SequenceNode {
		for _, label := range runner.Content {
			if isString(label) && strings.EqualFold(label.Value, "self-hosted") {
				return true
			}
		}
	}
	return false
}

func isCheckout(node *yaml.Node) bool {
	if !isString(node) {
		return false
	}
	location, _, found := strings.Cut(node.Value, "@")
	return found && strings.EqualFold(location, "actions/checkout")
}
