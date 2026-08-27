package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunJSON(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	var out bytes.Buffer
	code := run([]string{"--json", "--insecure", srv.URL}, &out, io.Discard)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; output:\n%s", code, out.String())
	}

	var rep jsonReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}
	if rep.Tool != "qcheck" || len(rep.Results) != 1 {
		t.Fatalf("unexpected report: %+v", rep)
	}
	if rep.Results[0].Verdict != "ready" {
		t.Fatalf("verdict = %q, want ready", rep.Results[0].Verdict)
	}
}

func TestRunGroupsJSON(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	var out bytes.Buffer
	code := run([]string{"--json", "--groups", "--insecure", srv.URL}, &out, io.Discard)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; output:\n%s", code, out.String())
	}
	var rep jsonReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Results[0].SupportedGroups) == 0 {
		t.Fatalf("expected supported_groups to be populated:\n%s", out.String())
	}
}

func TestRunBadResolveExits3(t *testing.T) {
	code := run([]string{"--resolve", "nonsense", "example.com"}, io.Discard, io.Discard)
	if code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
}

func TestRunText(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	var out bytes.Buffer
	code := run([]string{"--insecure", srv.URL}, &out, io.Discard)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	got := out.String()
	if !strings.Contains(got, "READY") || !strings.Contains(got, "Key exchange") {
		t.Fatalf("unexpected text output:\n%s", got)
	}
}

func TestRunInputFileAndDedup(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "sites.txt")
	body := "# comment\n" + srv.URL + "\n\n" + srv.URL + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	code := run([]string{"--json", "--insecure", "--input", path}, &out, io.Discard)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	var rep jsonReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("expected 1 de-duplicated result, got %d", len(rep.Results))
	}
}

func TestRunVersion(t *testing.T) {
	var out bytes.Buffer
	code := run([]string{"--version"}, &out, io.Discard)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.HasPrefix(out.String(), "qcheck ") {
		t.Fatalf("unexpected version output: %q", out.String())
	}
}

func TestRunNoTargets(t *testing.T) {
	var errBuf bytes.Buffer
	code := run(nil, io.Discard, &errBuf)
	if code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
	if !strings.Contains(errBuf.String(), "Usage") {
		t.Fatalf("expected usage output, got:\n%s", errBuf.String())
	}
}

func TestRunUnknownFlag(t *testing.T) {
	code := run([]string{"--bogus"}, io.Discard, io.Discard)
	if code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
}

func TestExitCode(t *testing.T) {
	tests := []struct {
		name    string
		verdict []Verdict
		strict  bool
		want    int
	}{
		{"all ready", []Verdict{VerdictReady, VerdictReady}, false, 0},
		{"capable is ok", []Verdict{VerdictReady, VerdictCapable}, false, 0},
		{"capable strict", []Verdict{VerdictReady, VerdictCapable}, true, 1},
		{"not ready", []Verdict{VerdictReady, VerdictNotReady}, false, 1},
		{"error wins", []Verdict{VerdictNotReady, VerdictError}, false, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := make([]Result, len(tt.verdict))
			for i, v := range tt.verdict {
				results[i] = Result{Verdict: v}
			}
			if got := exitCode(results, tt.strict); got != tt.want {
				t.Fatalf("exitCode() = %d, want %d", got, tt.want)
			}
		})
	}
}
