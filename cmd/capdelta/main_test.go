package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/themayursinha/capability-delta-receipts/capdelta"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

func runArgs(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	err := run(args, &buf)
	return buf.String(), err
}

func testdata(name string) string {
	return filepath.Join("..", "..", "testdata", name)
}

func validTrajectoryJSON() string {
	return `{
  "session_id": "demo-001",
  "envelope": {
    "declared_target": "v8-sandbox@container",
    "declared_network": "none",
    "declared_host": "unreachable"
  },
  "declared_authority": {
    "target": "v8-sandbox@container",
    "network": "none",
    "host": "unreachable",
    "intent": "run PoC A against declared target"
  },
  "events": [
    {
      "type": "runtime",
      "step_id": 1,
      "target": "v8-sandbox@container",
      "effect_target": "v8-sandbox@container",
      "marker": "memory_corruption",
      "observation": "OOB canary read/write at out-of-bounds offset",
      "digest": "sha256:5a5cd1bb9509b1e351a489e335f7f57cfd0639be030fd4ec6b66afe59b54f144"
    }
  ],
  "canary": {
    "path": "/host-canary/write.sh",
    "touched": false
  }
}`
}

func TestRunRejectsUnknownField(t *testing.T) {
	path := writeTemp(t, strings.Replace(validTrajectoryJSON(), `"touched": false
  }
}`, `"touched": false
  },
  "surprise": 1
}`, 1))
	out, err := runArgs(t, path)
	if err == nil {
		t.Fatal("expected error for unknown JSON field")
	}
	if out != "" {
		t.Fatalf("partial receipt on stdout: %q", out)
	}
}

func TestRunRejectsDuplicateKeys(t *testing.T) {
	path := writeTemp(t, strings.Replace(validTrajectoryJSON(), `"session_id": "demo-001",`, `"session_id": "demo-001",
  "session_id": "demo-002",`, 1))
	out, err := runArgs(t, path)
	if err == nil {
		t.Fatal("expected error for duplicate JSON key")
	}
	if out != "" {
		t.Fatalf("partial receipt on stdout: %q", out)
	}
}

func TestRunRejectsTrailingJSON(t *testing.T) {
	path := writeTemp(t, validTrajectoryJSON()+` {"again":1}`)
	out, err := runArgs(t, path)
	if err == nil {
		t.Fatal("expected error for trailing JSON")
	}
	if out != "" {
		t.Fatalf("partial receipt on stdout: %q", out)
	}
}

func TestRunRejectsTopLevelNonObject(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"array", `[1, 2, 3]`},
		{"null", `null`},
		{"string", `"trajectory"`},
		{"number", `1`},
		{"empty", ``},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTemp(t, tc.content)
			out, err := runArgs(t, path)
			if err == nil {
				t.Fatal("expected error for top-level non-object")
			}
			if out != "" {
				t.Fatalf("partial receipt on stdout: %q", out)
			}
		})
	}
}

func TestRunRejectsNullRequiredFields(t *testing.T) {
	valid := validTrajectoryJSON()
	cases := []struct {
		name   string
		mutate func() string
	}{
		{"null session_id", func() string {
			return strings.Replace(valid, `"session_id": "demo-001"`, `"session_id": null`, 1)
		}},
		{"null events", func() string {
			return strings.Replace(valid, `"events": [`, `"events": null, "dropped": [`, 1)
		}},
		{"null envelope", func() string {
			return strings.Replace(valid, `"envelope": {`, `"envelope": null, "dropped": {`, 1)
		}},
		{"null declared_authority", func() string {
			return strings.Replace(valid, `"declared_authority": {`, `"declared_authority": null, "dropped": {`, 1)
		}},
		{"null nested target", func() string {
			return strings.Replace(valid, `"target": "v8-sandbox@container",
    "network": "none"`, `"target": null,
    "network": "none"`, 1)
		}},
		{"null canary touched", func() string {
			return strings.Replace(valid, `"touched": false`, `"touched": null`, 1)
		}},
		{"null event type", func() string {
			return strings.Replace(valid, `"type": "runtime"`, `"type": null`, 1)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTemp(t, tc.mutate())
			out, err := runArgs(t, path)
			if err == nil {
				t.Fatal("expected error for null required field")
			}
			if out != "" {
				t.Fatalf("partial receipt on stdout: %q", out)
			}
		})
	}
}

func TestRunRejectsMalformedJSON(t *testing.T) {
	path := writeTemp(t, `{"session_id": "demo-001"`)
	out, err := runArgs(t, path)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if out != "" {
		t.Fatalf("partial receipt on stdout: %q", out)
	}
}

func TestRunRejectsUnreadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	out, err := runArgs(t, path)
	if err == nil {
		t.Fatal("expected error for unreadable file")
	}
	if out != "" {
		t.Fatalf("partial receipt on stdout: %q", out)
	}
}

func TestRunRequiresExactlyOneArgument(t *testing.T) {
	out, err := runArgs(t)
	if err == nil {
		t.Fatal("expected usage error with no arguments")
	}
	if out != "" {
		t.Fatalf("partial receipt on stdout: %q", out)
	}
	out, err = runArgs(t, "a.json", "b.json")
	if err == nil {
		t.Fatal("expected usage error with two arguments")
	}
	if out != "" {
		t.Fatalf("partial receipt on stdout: %q", out)
	}
}

// TestRunRejectsStrictShapeViolations proves the decoder is strict about
// more than unknown fields: case-variant names, null array elements,
// unknown nested fields, duplicate nested keys, and type mismatches are
// process errors with no partial receipt.
func TestRunRejectsStrictShapeViolations(t *testing.T) {
	valid := validTrajectoryJSON()
	cases := []struct {
		name   string
		mutate func() string
	}{
		{"case-variant field name", func() string {
			return strings.Replace(valid, `"session_id": "demo-001"`, `"SESSION_ID": "demo-001"`, 1)
		}},
		{"null element in events", func() string {
			return strings.Replace(valid, `{
      "type": "runtime"`, `null, {
      "type": "runtime"`, 1)
		}},
		{"unknown nested field", func() string {
			return strings.Replace(valid, `"marker": "memory_corruption",`, `"marker": "memory_corruption",
      "surprise": 1,`, 1)
		}},
		{"duplicate nested key", func() string {
			return strings.Replace(valid, `"type": "runtime",`, `"type": "runtime",
      "type": "runtime",`, 1)
		}},
		{"type mismatch bool field", func() string {
			return strings.Replace(valid, `"touched": false`, `"touched": "no"`, 1)
		}},
		{"type mismatch step_id", func() string {
			return strings.Replace(valid, `"step_id": 1`, `"step_id": "1"`, 1)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTemp(t, tc.mutate())
			out, err := runArgs(t, path)
			if err == nil {
				t.Fatal("expected error for strict shape violation")
			}
			if out != "" {
				t.Fatalf("partial receipt on stdout: %q", out)
			}
		})
	}
}

func TestRunAllowIsAnAuthorizationResult(t *testing.T) {
	out, err := runArgs(t, testdata("allow-bug-a.json"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out == "" {
		t.Fatal("expected ALLOW receipt on stdout")
	}
	var receipt capdelta.Receipt
	if err := json.Unmarshal([]byte(out), &receipt); err != nil {
		t.Fatalf("stdout is not a valid receipt: %v", err)
	}
	if receipt.Decision != capdelta.DecisionAllow {
		t.Fatalf("Decision = %q, want %q", receipt.Decision, capdelta.DecisionAllow)
	}
}

func TestRunPauseIsAnAuthorizationResult(t *testing.T) {
	out, err := runArgs(t, testdata("pause-egress.json"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out == "" {
		t.Fatal("expected PAUSE receipt on stdout")
	}
	var receipt capdelta.Receipt
	if err := json.Unmarshal([]byte(out), &receipt); err != nil {
		t.Fatalf("stdout is not a valid receipt: %v", err)
	}
	if receipt.Decision != capdelta.DecisionPause {
		t.Fatalf("Decision = %q, want %q", receipt.Decision, capdelta.DecisionPause)
	}
}

func TestRunGoldenFixtures(t *testing.T) {
	fixtures := []string{
		"allow-bug-a",
		"allow-bug-b",
		"pause-composition",
		"pause-egress",
		"allow-full-research",
	}
	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			expected, err := os.ReadFile(testdata(name + ".expected.json"))
			if err != nil {
				t.Fatalf("read expected fixture: %v", err)
			}
			out, err := runArgs(t, testdata(name+".json"))
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if out != string(expected) {
				t.Fatalf("stdout mismatch:\n--- got ---\n%s\n--- want ---\n%s", out, expected)
			}
		})
	}
}
