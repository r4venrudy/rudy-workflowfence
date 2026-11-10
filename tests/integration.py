"""Exercise the compiled command against inert workflow fixtures."""
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

binary, project = (Path(arg).resolve() for arg in sys.argv[1:])
checks = 0


def check(condition, message):
    global checks
    if not condition:
        raise AssertionError(message)
    checks += 1


def command(*args, status=0):
    completed = subprocess.run([binary, *map(str, args)], capture_output=True,
                               encoding="utf-8", timeout=15)
    check(completed.returncode == status, (args, completed))
    check(bool(completed.stderr) == (status == 2), completed.stderr)
    return completed.stdout


def analyze(root, *flags, status=0):
    return json.loads(command("--root", root, "--format", "json", *flags, status=status))


safe = project / "examples/safe"
review = project / "examples/review"
check(command("--version").strip() == "workflowfence 0.1.0-preview", "version")
report = analyze(safe)
check(report["findings"] == [] and report["workflows"] == 1, report)
check(report["dependencies"][0]["immutable"], report)
report = analyze(review, status=1)
expected = {"WF001", "WF002", "WF006", "WF007"}
check({finding["rule"] for finding in report["findings"]} == expected, report)
check(report == analyze(review, "--fail-on", "never"), "threshold changed report")
for finding in report["findings"]:
    check(finding["line"] >= 1 and finding["path"].endswith("check.yml"), finding)
    if finding["rule"] != "WF002":
        check(finding["via"] == [".github/workflows/caller.yml", ".github/workflows/check.yml"], finding)
first = command("--root", review, "--format", "json", status=1)
check(first == command("--root", review, "--format", "json", status=1), "unstable report bytes")
text = command("--root", review, status=1)
check("via .github/workflows/caller.yml -> .github/workflows/check.yml" in text, text)
check("printf" not in text and "printf" not in first, "report included shell source")
sarif = json.loads(command("--root", review, "--format", "sarif", status=1))
check(sarif["version"] == "2.1.0", sarif)
run = sarif["runs"][0]
check(len(run["tool"]["driver"]["rules"]) == 12, run)
check({r["ruleId"] for r in run["results"]} == expected, run)
for result in run["results"]:
    loc = result["locations"][0]["physicalLocation"]
    check(loc["artifactLocation"]["uri"] == ".github/workflows/check.yml", result)
    check(loc["region"]["startLine"] >= 1 and result["level"] in ("warning", "error"), result)

with TemporaryDirectory() as directory:
    root = Path(directory)
    command("--root", root, status=2)
    workflows = root / ".github/workflows"
    workflows.mkdir(parents=True)
    test = workflows / "test.yml"
    test.write_text("on: push\npermissions: {}\njobs: {verify: {steps: [{uses: actions/checkout@v7}]}}\n",
                    encoding="utf-8")
    check(len(analyze(root)["findings"]) == 1, "medium finding expected")
    check(analyze(root, "--fail-on", "medium", status=1)["findings"][0]["rule"] == "WF002",
          "medium gate")
    test.write_text("on: push\non: pull_request\njobs: {verify: {}}\n", encoding="utf-8")
    command("--root", root, status=2)
    test.write_bytes(b"#" * (256 * 1024 + 1))
    command("--root", root, status=2)
    test.unlink()
    target = root / "target.txt"
    target.write_text("on: push\njobs: {a: {}}\n", encoding="utf-8")
    try:
        test.symlink_to(target)
    except OSError:
        pass
    else:
        command("--root", root, status=2)

command("--format", "xml", status=2)
command("--fail-on", "low", status=2)
print(f"{checks} CLI checks across workflow parsing, trust paths, reporting and gating")
