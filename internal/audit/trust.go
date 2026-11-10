package audit

import (
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

type Finding struct {
	Rule     string   `json:"rule"`
	Severity string   `json:"severity"`
	Path     string   `json:"path"`
	Line     int      `json:"line"`
	Job      string   `json:"job,omitempty"`
	Message  string   `json:"message"`
	Via      []string `json:"via,omitempty"`
}

func (workflow Workflow) finding(rule, severity string, line int, job, message string, via []string) Finding {
	return Finding{Rule: rule, Severity: severity, Path: workflow.Path, Line: line, Job: job, Message: message, Via: via}
}

type trust uint8

const (
	external trust = 1 << iota
	privileged
)

func events(workflow Workflow) []string {
	on := lookup(workflow.root, "on")
	switch on.Kind {
	case yaml.SequenceNode:
		list := make([]string, 0, len(on.Content))
		for _, node := range on.Content {
			list = append(list, node.Value)
		}
		return list
	case yaml.MappingNode:
		list := make([]string, 0, len(on.Content)/2)
		for i := 0; i < len(on.Content); i += 2 {
			list = append(list, on.Content[i].Value)
		}
		return list
	default:
		return []string{on.Value}
	}
}

func eventTrust(list []string) trust {
	var result trust
	for _, name := range list {
		switch name {
		case "pull_request", "pull_request_review", "pull_request_review_comment":
			result |= external
		case "pull_request_target", "workflow_run", "issues", "issue_comment", "discussion", "discussion_comment":
			result |= external | privileged
		}
	}
	return result
}

type permissions struct {
	declared bool
	valid    bool
	all      bool
	write    []string
}

func permissionSet(node *yaml.Node) permissions {
	if node == nil {
		return permissions{}
	}
	result := permissions{declared: true, valid: true}
	if isString(node) {
		switch node.Value {
		case "write-all":
			result.all = true
		case "read-all":
		default:
			result.valid = false
		}
		return result
	}
	if node.Kind != yaml.MappingNode {
		result.valid = false
		return result
	}
	for i := 0; i < len(node.Content); i += 2 {
		value := node.Content[i+1]
		if !isString(value) {
			result.valid = false
			continue
		}
		switch value.Value {
		case "write":
			result.write = append(result.write, node.Content[i].Value)
		case "read", "none":
		default:
			result.valid = false
		}
	}
	slices.Sort(result.write)
	return result
}

func jobPermissions(workflow Workflow, job *yaml.Node) permissions {
	if own := lookup(job, "permissions"); own != nil {
		return permissionSet(own)
	}
	return permissionSet(lookup(workflow.root, "permissions"))
}

func (p permissions) canWrite() bool { return p.all || len(p.write) > 0 }

func (p permissions) description() string {
	if p.all {
		return "write-all"
	}
	return strings.Join(p.write, ", ")
}

type jobNode struct {
	name string
	node *yaml.Node
}

func jobs(workflow Workflow) []jobNode {
	mapping := lookup(workflow.root, "jobs")
	list := make([]jobNode, 0, len(mapping.Content)/2)
	for i := 0; i < len(mapping.Content); i += 2 {
		list = append(list, jobNode{mapping.Content[i].Value, mapping.Content[i+1]})
	}
	return list
}

func steps(job *yaml.Node) []*yaml.Node {
	if list := lookup(job, "steps"); list != nil {
		return list.Content
	}
	return nil
}
