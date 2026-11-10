package audit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	workflowDir   = ".github/workflows"
	maxFiles      = 128
	maxBytes      = 256 * 1024
	maxTotalBytes = 4 * 1024 * 1024
	maxNodes      = 32_768
	maxDepth      = 48
)

type Workflow struct {
	Path string
	root *yaml.Node
}

func Load(rootPath string) ([]Workflow, error) {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(workflowDir)
	if err != nil {
		return nil, fmt.Errorf("workflow directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("workflow directory is not a directory")
	}
	dir, err := root.Open(workflowDir)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(maxFiles + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > maxFiles {
		return nil, fmt.Errorf("workflow directory exceeds %d entries", maxFiles)
	}
	slices.SortFunc(entries, func(a, b fs.DirEntry) int {
		return strings.Compare(a.Name(), b.Name())
	})
	workflows := make([]Workflow, 0, len(entries))
	totalBytes := 0
	for _, entry := range entries {
		ext := filepath.Ext(entry.Name())
		if ext != ".yml" && ext != ".yaml" {
			continue
		}
		if !entry.Type().IsRegular() {
			return nil, fmt.Errorf("%s: workflow must be a regular file", entry.Name())
		}
		path := workflowDir + "/" + entry.Name()
		content, err := readWorkflow(root, path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		totalBytes += len(content)
		if totalBytes > maxTotalBytes {
			return nil, fmt.Errorf("workflows exceed %d bytes in aggregate", maxTotalBytes)
		}
		workflow, err := Parse(path, content)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		workflows = append(workflows, workflow)
	}
	if len(workflows) == 0 {
		return nil, fmt.Errorf("no YAML workflows found in %s", workflowDir)
	}
	return workflows, nil
}

func readWorkflow(root *os.Root, path string) ([]byte, error) {
	info, err := root.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxBytes {
		return nil, fmt.Errorf("workflow must be a regular file of at most %d bytes", maxBytes)
	}
	file, err := root.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, opened) {
		return nil, fmt.Errorf("workflow changed while opening")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err == nil && len(content) > maxBytes {
		return nil, fmt.Errorf("workflow exceeds %d bytes", maxBytes)
	}
	return content, err
}

func Parse(path string, content []byte) (Workflow, error) {
	if len(content) > maxBytes {
		return Workflow{}, fmt.Errorf("workflow exceeds %d bytes", maxBytes)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	var document, extra yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return Workflow{}, err
	}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Workflow{}, fmt.Errorf("expected exactly one YAML document")
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return Workflow{}, fmt.Errorf("expected a workflow mapping")
	}
	nodes := 0
	root := document.Content[0]
	if err := validate(root, 1, &nodes); err != nil {
		return Workflow{}, err
	}
	on := lookup(root, "on")
	jobs := lookup(root, "jobs")
	if on == nil || jobs == nil || jobs.Kind != yaml.MappingNode || len(jobs.Content) == 0 {
		return Workflow{}, fmt.Errorf("expected on and a nonempty jobs mapping")
	}
	switch on.Kind {
	case yaml.ScalarNode:
		if !isString(on) || on.Value == "" {
			return Workflow{}, fmt.Errorf("line %d: expected a trigger name", on.Line)
		}
	case yaml.SequenceNode:
		if len(on.Content) == 0 {
			return Workflow{}, fmt.Errorf("line %d: expected at least one trigger", on.Line)
		}
		for _, trigger := range on.Content {
			if !isString(trigger) || trigger.Value == "" {
				return Workflow{}, fmt.Errorf("line %d: expected a trigger name", trigger.Line)
			}
		}
	case yaml.MappingNode:
		if len(on.Content) == 0 {
			return Workflow{}, fmt.Errorf("line %d: expected at least one trigger", on.Line)
		}
	default:
		return Workflow{}, fmt.Errorf("line %d: invalid trigger definition", on.Line)
	}
	for i := 1; i < len(jobs.Content); i += 2 {
		job := jobs.Content[i]
		if job.Kind != yaml.MappingNode {
			return Workflow{}, fmt.Errorf("line %d: expected a job mapping", job.Line)
		}
		steps := lookup(job, "steps")
		if steps != nil {
			if steps.Kind != yaml.SequenceNode {
				return Workflow{}, fmt.Errorf("line %d: expected a step list", steps.Line)
			}
			for _, step := range steps.Content {
				if step.Kind != yaml.MappingNode {
					return Workflow{}, fmt.Errorf("line %d: expected a step mapping", step.Line)
				}
			}
		}
	}
	return Workflow{Path: path, root: root}, nil
}

func validate(node *yaml.Node, depth int, count *int) error {
	*count += 1
	if depth > maxDepth || *count > maxNodes {
		return fmt.Errorf("line %d: YAML complexity exceeds limits", node.Line)
	}
	if node.Anchor != "" || node.Kind == yaml.AliasNode {
		return fmt.Errorf("line %d: YAML anchors and aliases are outside the audit profile", node.Line)
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]struct{}, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if !isString(key) || key.Value == "" || key.Value == "<<" {
				return fmt.Errorf("line %d: expected a nonempty string key", key.Line)
			}
			if _, found := seen[key.Value]; found {
				return fmt.Errorf("line %d: duplicate mapping key", key.Line)
			}
			seen[key.Value] = struct{}{}
		}
	}
	for _, child := range node.Content {
		if err := validate(child, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}

func isString(node *yaml.Node) bool {
	return node != nil && node.Kind == yaml.ScalarNode && node.ShortTag() == "!!str"
}

func lookup(node *yaml.Node, name string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == name {
			return node.Content[i+1]
		}
	}
	return nil
}
