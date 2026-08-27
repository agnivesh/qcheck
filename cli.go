package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Build metadata, overridden at release time via -ldflags -X main.<name>=...
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type config struct {
	json        bool
	timeout     time.Duration
	insecure    bool
	concurrency int
	inputFile   string
	strict      bool
}

// run parses args, probes every target concurrently, renders a report to stdout,
// and returns a process exit code. It never calls os.Exit, so tests can call it
// directly.
//
// Exit codes: 0 every target ready (capable too, unless --strict); 1 a target is
// not ready (or only capable under --strict); 2 a target errored; 3 usage error.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("qcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr, fs) }

	var cfg config
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.BoolVar(&cfg.json, "json", false, "emit a JSON report instead of text")
	fs.DurationVar(&cfg.timeout, "timeout", 10*time.Second, "per-handshake timeout")
	fs.BoolVar(&cfg.insecure, "insecure", false, "skip certificate verification")
	fs.IntVar(&cfg.concurrency, "concurrency", 0, "max concurrent probes (default: min(targets, 8))")
	fs.StringVar(&cfg.inputFile, "input", "", "read targets from a file, one per line (\"-\" for stdin)")
	fs.BoolVar(&cfg.strict, "strict", false, "exit non-zero unless every target is READY")

	if err := fs.Parse(args); err != nil {
		return 3
	}

	if *showVersion {
		fmt.Fprintf(stdout, "qcheck %s (commit %s, built %s)\n", version, commit, date)
		return 0
	}

	targets, err := collectTargets(fs.Args(), cfg.inputFile, stdin(stdout))
	if err != nil {
		fmt.Fprintln(stderr, "qcheck:", err)
		return 3
	}
	if len(targets) == 0 {
		usage(stderr, fs)
		return 3
	}

	conc := cfg.concurrency
	if conc <= 0 {
		conc = min(len(targets), 8)
	}

	opts := Options{Timeout: cfg.timeout, InsecureSkipVerify: cfg.insecure}
	results := probeAll(context.Background(), targets, opts, conc)

	if cfg.json {
		if err := RenderJSON(stdout, results); err != nil {
			fmt.Fprintln(stderr, "qcheck:", err)
			return 3
		}
	} else {
		RenderText(stdout, results, isTerminal(stdout))
	}
	return exitCode(results, cfg.strict)
}

// probeAll probes targets with at most concurrency handshakes in flight,
// preserving input order in the returned slice.
func probeAll(ctx context.Context, targets []string, opts Options, concurrency int) []Result {
	results := make([]Result, len(targets))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, t := range targets {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			results[i] = Probe(ctx, t, opts)
		})
	}
	wg.Wait()
	return results
}

func exitCode(results []Result, strict bool) int {
	code := 0
	for _, r := range results {
		switch r.Verdict {
		case VerdictError:
			code = max(code, 2)
		case VerdictNotReady:
			code = max(code, 1)
		case VerdictCapable:
			if strict {
				code = max(code, 1)
			}
		case VerdictReady:
		}
	}
	return code
}

// collectTargets gathers targets from positional args and, if set, an input file
// ("-" reads from in). Order is preserved, blanks and "#" comments are dropped,
// and duplicates are removed.
func collectTargets(posArgs []string, inputFile string, in io.Reader) ([]string, error) {
	seen := make(map[string]bool)
	var targets []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") || seen[s] {
			return
		}
		seen[s] = true
		targets = append(targets, s)
	}

	for _, a := range posArgs {
		add(a)
	}

	if inputFile == "" {
		return targets, nil
	}

	r := in
	if inputFile != "-" {
		f, err := os.Open(inputFile)
		if err != nil {
			return nil, fmt.Errorf("opening --input file: %w", err)
		}
		defer f.Close()
		r = f
	}

	sc := bufio.NewScanner(r)
	for sc.Scan() {
		add(sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading --input file: %w", err)
	}
	return targets, nil
}

func usage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintln(w, "qcheck - check whether a site's TLS is post-quantum ready")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  qcheck [flags] <site>...")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fs.PrintDefaults()
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Exit codes: 0 all ready   1 not ready   2 error   3 usage")
}

// stdin returns os.Stdin unless stdout has been redirected to something that is
// not the real stdout (i.e. a test), in which case reading real stdin would be
// wrong; callers only use the result when --input is "-".
func stdin(stdout io.Writer) io.Reader {
	if stdout == os.Stdout {
		return os.Stdin
	}
	return strings.NewReader("")
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
