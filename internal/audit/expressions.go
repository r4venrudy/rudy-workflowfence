package audit

import "strings"

var textSources = []string{
	"github.head_ref", "github.event",
	"github.event.pull_request.title", "github.event.pull_request.body",
	"github.event.pull_request.head.ref", "github.event.pull_request.head.label",
	"github.event.issue.title", "github.event.issue.body", "github.event.comment.body",
	"github.event.review.body", "github.event.discussion.title", "github.event.discussion.body",
	"github.event.head_commit.message", "github.event.commits", "github.event.workflow_run.head_branch",
}

var checkoutSources = []string{
	"github.head_ref", "github.event.pull_request.head.sha",
	"github.event.pull_request.head.ref", "github.event.pull_request.head.repo.full_name",
	"github.event.pull_request.merge_commit_sha", "github.event.workflow_run.head_sha",
	"github.event.workflow_run.head_branch", "github.event.workflow_run.head_repository.full_name",
}

func expressionSource(input string, sources []string) bool {
	for {
		start := strings.Index(input, "${{")
		if start < 0 {
			return false
		}
		input = input[start+3:]
		end := expressionEnd(input)
		if end < 0 {
			return false
		}
		for _, reference := range expressionPaths(input[:end]) {
			for _, source := range sources {
				if reference == source || (source != "github.event" && strings.HasPrefix(reference, source+".")) {
					return true
				}
			}
		}
		input = input[end+2:]
	}
}

func expressionEnd(expression string) int {
	for i := 0; i+1 < len(expression); {
		switch {
		case expression[i] == '\'':
			_, next, ok := quoted(expression, i)
			if !ok {
				return -1
			}
			i = next
		case expression[i] == '}' && expression[i+1] == '}':
			return i
		default:
			i++
		}
	}
	return -1
}

func expressionPaths(expression string) []string {
	paths := []string{}
	for i := 0; i < len(expression); {
		if expression[i] == '\'' {
			_, next, ok := quoted(expression, i)
			if !ok {
				break
			}
			i = next
			continue
		}
		if !letter(expression[i]) {
			i++
			continue
		}
		end := wordEnd(expression, i)
		var path strings.Builder
		path.WriteString(expression[i:end])
		i = end
		for {
			start := skipSpace(expression, i)
			if start == len(expression) {
				break
			}
			if expression[start] == '.' {
				part := skipSpace(expression, start+1)
				if part == len(expression) || !letter(expression[part]) {
					break
				}
				end := wordEnd(expression, part)
				path.WriteByte('.')
				path.WriteString(expression[part:end])
				i = end
			} else if expression[start] == '[' {
				part := skipSpace(expression, start+1)
				if part == len(expression) || expression[part] != '\'' {
					break
				}
				name, after, ok := quoted(expression, part)
				end := skipSpace(expression, after)
				if !ok || end == len(expression) || expression[end] != ']' {
					break
				}
				if name == "" || !letter(name[0]) || wordEnd(name, 0) != len(name) {
					break
				}
				path.WriteByte('.')
				path.WriteString(name)
				i = end + 1
			} else {
				break
			}
		}
		paths = append(paths, strings.ToLower(path.String()))
	}
	return paths
}

func quoted(text string, start int) (string, int, bool) {
	var content strings.Builder
	for i := start + 1; i < len(text); i++ {
		if text[i] == '\'' {
			if i+1 == len(text) || text[i+1] != '\'' {
				return content.String(), i + 1, true
			}
			i++
		}
		content.WriteByte(text[i])
	}
	return "", len(text), false
}

func letter(b byte) bool { return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b == '_' }

func wordEnd(text string, start int) int {
	for start < len(text) {
		b := text[start]
		if !letter(b) && !(b >= '0' && b <= '9') && b != '-' {
			break
		}
		start++
	}
	return start
}

func skipSpace(text string, start int) int {
	for start < len(text) && strings.ContainsRune(" \t\r\n", rune(text[start])) {
		start++
	}
	return start
}
