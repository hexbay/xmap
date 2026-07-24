package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hexbay/xmap/pkg/api"
	"github.com/hexbay/xmap/pkg/types"
)

type target struct {
	Name, Target, Expected, Protocol string
	Accepted                         []string
	RequireSSL                       bool
}
type catalogEntry struct{ Protocol, Transport, Mode, Tier string }
type row struct {
	target
	Actual   string
	SSL      bool
	Duration float64
	Passed   bool
	Error    string
}

func main() {
	config := "testlab/targets.json"
	output := "testlab-report.md"
	if len(os.Args) > 1 {
		output = os.Args[1]
	}
	// CI must exercise the repository's complete probe database, never an
	// incidental $HOME/finger-rules checkout from the runner image.
	if err := os.Setenv("NMAP_PROBE_FILE", "pkg/probe/nmap-service-probes"); err != nil {
		panic(err)
	}
	b, err := os.ReadFile(config)
	if err != nil {
		panic(err)
	}
	var targets []target
	if err := json.Unmarshal(b, &targets); err != nil {
		panic(err)
	}
	catalogData, err := os.ReadFile("testlab/top30.json")
	if err != nil {
		panic(err)
	}
	var catalog []catalogEntry
	if err := json.Unmarshal(catalogData, &catalog); err != nil {
		panic(err)
	}
	opts := types.DefaultOptions()
	opts.Timeout = 2
	opts.MaxTimeout = 8
	opts.VersionIntensity = 9
	// The lab intentionally verifies protocol signatures, not the production
	// fast-path.  Run the complete probe set so a banner on a standard port can
	// be matched by its generic/fallback probe as well as a port-specific one.
	opts.UseAllProbes = true
	x, err := api.New(opts)
	if err != nil {
		panic(err)
	}
	rows := make([]row, 0, len(targets))
	passed := 0
	totalSeconds := 0.0
	for _, item := range targets {
		started := time.Now()
		result, scanErr := x.Scan(context.Background(), types.NewTarget(item.Target))
		r := row{target: item, Duration: time.Since(started).Seconds()}
		if result != nil {
			r.Actual = result.Service
			r.SSL = result.SSL
			r.Duration = result.Duration
		}
		if scanErr != nil {
			r.Error = scanErr.Error()
		}
		r.Passed = matchesExpected(r)
		if r.Passed {
			passed++
		}
		totalSeconds += r.Duration
		if r.Protocol == "" {
			r.Protocol = r.Expected
		}
		rows = append(rows, r)
	}
	f, err := os.Create(filepath.Clean(output))
	if err != nil {
		panic(err)
	}
	defer f.Close()
	fmt.Fprintf(f, "# xmap Protocol Test Report\n\n")
	covered := make(map[string]bool, len(rows))
	for _, r := range rows {
		if r.Passed {
			covered[r.Protocol] = true
		}
	}
	coveredCount := 0
	for _, entry := range catalog {
		if covered[entry.Protocol] {
			coveredCount++
		}
	}
	fmt.Fprintf(f, "Top-30 passing coverage: **%d/%d (%.1f%%)**  \n", coveredCount, len(catalog), float64(coveredCount)*100/float64(len(catalog)))
	fmt.Fprintf(f, "Integrated services: **%d/%d**; integrated pass rate: **%d/%d (%.1f%%)**  \n", len(rows), len(rows), passed, len(rows), float64(passed)*100/float64(len(rows)))
	fmt.Fprintf(f, "Total scan time: **%.3fs**; average: **%.3fs**\n\n", totalSeconds, totalSeconds/float64(len(rows)))
	fmt.Fprintln(f, "| Service | Expected | Detected | Time | Result |")
	fmt.Fprintln(f, "|---|---|---|---:|---|")
	for _, r := range rows {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
			if r.Error != "" {
				status += ": " + r.Error
			}
		}
		fmt.Fprintf(f, "| %s | %s | %s | %.3fs | %s |\n", r.Name, r.Expected, r.Actual, r.Duration, status)
	}
	configured := make(map[string]bool, len(rows))
	for _, r := range rows {
		configured[r.Protocol] = true
	}
	fmt.Fprintln(f, "\n## Pending protocol coverage")
	fmt.Fprintln(f)
	pending := 0
	for _, entry := range catalog {
		if !configured[entry.Protocol] {
			fmt.Fprintf(f, "- `%s` (%s, %s, %s)\n", entry.Protocol, entry.Transport, entry.Mode, entry.Tier)
			pending++
		}
	}
	if pending == 0 {
		fmt.Fprintln(f, "All Top-30 catalog entries have a provisioned test target.")
	}
	if passed != len(rows) {
		os.Exit(1)
	}
}

func matchesExpected(r row) bool {
	accepted := r.Accepted
	if len(accepted) == 0 {
		accepted = []string{r.Expected}
	}
	for _, service := range accepted {
		if r.Actual == service {
			return !r.RequireSSL || r.SSL
		}
	}
	return false
}
