package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"github.com/r4venrudy/rudy-workflowfence/internal/audit"
)

const version = "0.1.0-preview"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, out, errOut io.Writer) int {
	options := flag.NewFlagSet("workflowfence", flag.ContinueOnError)
	options.SetOutput(errOut)
	root := options.String("root", ".", "local repository root")
	format := options.String("format", "text", "text, json, or sarif")
	gate := options.String("fail-on", "high", "high, medium, or never")
	showVersion := options.Bool("version", false, "show the CLI version")
	if err := options.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if options.NArg() != 0 || !oneOf(*format, "text", "json", "sarif") ||
		!oneOf(*gate, "high", "medium", "never") {
		fmt.Fprintln(errOut, "workflowfence: invalid argument, output format, or threshold")
		return 2
	}
	if *showVersion {
		fmt.Fprintln(out, "workflowfence "+version)
		return 0
	}

	workflows, err := audit.Load(*root)
	if err != nil {
		fmt.Fprintln(errOut, "workflowfence:", plain(err.Error()))
		return 2
	}
	report := audit.Analyze(workflows)
	switch *format {
	case "text":
		err = writeText(out, report)
	case "json", "sarif":
		var payload any = report
		if *format == "sarif" {
			payload = sarif(report)
		}
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(payload)
	}
	if err != nil {
		fmt.Fprintln(errOut, "workflowfence: could not write report:", plain(err.Error()))
		return 2
	}
	if report.Blocks(*gate) {
		return 1
	}
	return 0
}

func oneOf(value string, values ...string) bool {
	for _, choice := range values {
		if value == choice {
			return true
		}
	}
	return false
}

func plain(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return '?'
		}
		return r
	}, value)
}

func writeText(out io.Writer, report audit.Report) error {
	for _, finding := range report.Findings {
		_, err := fmt.Fprintf(out, "%s:%d %s %s %s\n",
			plain(finding.Path), finding.Line, finding.Severity, finding.Rule, plain(finding.Message))
		if err != nil {
			return err
		}
		if len(finding.Via) > 1 {
			if _, err := fmt.Fprintln(out, "  via "+plain(strings.Join(finding.Via, " -> "))); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintf(out, "%d workflow(s), %d dependency reference(s), %d finding(s)\n",
		report.Workflows, len(report.Dependencies), len(report.Findings))
	return err
}
