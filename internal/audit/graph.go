package audit

import (
	"path"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

var (
	fullCommit = regexp.MustCompile("^[0-9a-fA-F]{40}$")
	imageHash  = regexp.MustCompile("^[0-9a-fA-F]{64}$")
	safePath   = regexp.MustCompile("^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$")
)

type Dependency struct {
	Path      string `json:"path"`
	Line      int    `json:"line"`
	Job       string `json:"job"`
	Kind      string `json:"kind"`
	Reference string `json:"reference,omitempty"`
	Immutable bool   `json:"immutable"`
}

func classify(workflow Workflow, job string, node *yaml.Node, reusable bool) Dependency {
	dep := Dependency{Path: workflow.Path, Line: node.Line, Job: job, Kind: "unresolved"}
	if !isString(node) {
		return dep
	}
	ref := node.Value
	if strings.HasPrefix(ref, "./") {
		local := strings.TrimPrefix(ref, "./")
		if !safePath.MatchString(local) || path.Clean(local) != local || local == ".." || strings.HasPrefix(local, "../") {
			return dep
		}
		dep.Reference, dep.Immutable = local, true
		if reusable {
			dep.Kind = "local-workflow"
		} else {
			dep.Kind = "local-action"
		}
		return dep
	}
	if strings.HasPrefix(ref, "docker://") && !reusable {
		image, digest, ok := strings.Cut(strings.TrimPrefix(ref, "docker://"), "@sha256:")
		if ok && image != "" && imageHash.MatchString(digest) {
			dep.Immutable = true
		}
		dep.Kind = "container-action"
		if !strings.ContainsAny(ref, " \r\n\t{}$") {
			dep.Reference = ref
		}
		return dep
	}
	location, version, ok := strings.Cut(ref, "@")
	if !ok || !safePath.MatchString(location) || !strings.Contains(location, "/") ||
		path.Clean(location) != location || strings.HasPrefix(location, "../") {
		return dep
	}
	dep.Reference = location
	dep.Kind = "remote-action"
	if reusable {
		dep.Kind = "remote-workflow"
	}
	dep.Immutable = fullCommit.MatchString(version)
	if dep.Immutable {
		dep.Reference += "@" + version
	}
	return dep
}

type edge struct {
	target int
	line   int
	job    string
}

type graph struct {
	nodes []Workflow
	edges [][]edge
}

func buildGraph(workflows []Workflow) (graph, []Dependency, []Finding) {
	workflows = slices.Clone(workflows)
	slices.SortFunc(workflows, func(a, b Workflow) int { return strings.Compare(a.Path, b.Path) })
	graph := graph{nodes: workflows, edges: make([][]edge, len(workflows))}
	index := make(map[string]int, len(workflows))
	for i, workflow := range workflows {
		index[workflow.Path] = i
	}
	deps := []Dependency{}
	findings := []Finding{}
	for i, workflow := range workflows {
		add := func(job string, value *yaml.Node, reusable bool) {
			dep := classify(workflow, job, value, reusable)
			deps = append(deps, dep)
			switch dep.Kind {
			case "local-workflow":
				target, found := index[dep.Reference]
				if !found || !slices.Contains(events(workflows[target]), "workflow_call") {
					findings = append(findings, workflow.finding("WF008", "high", dep.Line, job,
						"Local reusable workflow is missing or does not declare workflow_call.", nil))
				} else {
					graph.edges[i] = append(graph.edges[i], edge{target, dep.Line, job})
				}
			case "local-action":
				// Local action definitions are outside this workflow-only graph.
			case "unresolved":
				findings = append(findings, workflow.finding("WF009", "medium", dep.Line, job,
					"Dependency cannot be classified as a static workflow or action reference.", nil))
			default:
				if !dep.Immutable {
					findings = append(findings, workflow.finding("WF002", "medium", dep.Line, job,
						"Pin the dependency to a full commit SHA or container image digest.", nil))
				}
			}
		}
		for _, job := range jobs(workflow) {
			if uses := lookup(job.node, "uses"); uses != nil {
				add(job.name, uses, true)
			}
			for _, step := range steps(job.node) {
				if uses := lookup(step, "uses"); uses != nil {
					add(job.name, uses, false)
				}
			}
		}
	}
	return graph, deps, append(findings, graph.cycles()...)
}

func (graph graph) cycles() []Finding {
	color := make([]uint8, len(graph.nodes))
	findings := []Finding{}
	var visit func(int)
	visit = func(i int) {
		color[i] = 1
		for _, edge := range graph.edges[i] {
			switch color[edge.target] {
			case 0:
				visit(edge.target)
			case 1:
				findings = append(findings, graph.nodes[i].finding("WF010", "high", edge.line, edge.job,
					"Local reusable workflows form a cycle.", []string{graph.nodes[i].Path, graph.nodes[edge.target].Path}))
			}
		}
		color[i] = 2
	}
	for index := range graph.nodes {
		if color[index] == 0 {
			visit(index)
		}
	}
	return findings
}

// witnesses performs a multi-source breadth-first walk. The first path is
// a shortest witness from a directly triggered workflow to each local callee.
func (graph graph) witnesses(kind trust) [][]string {
	result := make([][]string, len(graph.nodes))
	queue := make([]int, 0, len(graph.nodes))
	for index, workflow := range graph.nodes {
		if eventTrust(events(workflow))&kind != 0 {
			result[index] = []string{workflow.Path}
			queue = append(queue, index)
		}
	}
	for next := 0; next < len(queue); next++ {
		source := queue[next]
		for _, edge := range graph.edges[source] {
			if result[edge.target] == nil {
				result[edge.target] = append(slices.Clone(result[source]), graph.nodes[edge.target].Path)
				queue = append(queue, edge.target)
			}
		}
	}
	return result
}
