// This program measures for which values of Λ the attack works. In the attack,
// one malicious Nudge server adds a large integer Λ to its share of the
// victim's entry of the product of the ratings matrix and the current vector,
// in the last iteration (see AttackRun), so that the victim's rated items
// become the largest coordinates of the first model row the servers reveal.
//
// For each victim of a synthetic matrix, the program runs the attack for every
// Λ = 2^e with e from -from to -to, with both start vectors of power iteration
// (all-ones or random), -repeats times each (the random start differs from run to run).
// It writes one line per run to a CSV file. It then prints the predicted
// lowest and highest Λ (see VictimBounds) and, below them, the exponents
// at which the runs actually leaked, so one can check that the attack starts
// and stops where predicted. Where only some runs leaked, it also says how
// many of the others had negative honest values (see AttackRun). It also shows in how many runs the attack revealed
// the victim's items when the attacker used its own choice of Λ, the one it
// computes from the total number of ratings and the victim's number of ratings
// (see AttackerExponent).
//
//	make run CMD=./attacks/leakageAttack/cmd/sweep ARGS="-matrix 80x24"
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	leakageattack "github.com/NudgeArtifact/private-recs/attacks/leakageAttack"
	"github.com/NudgeArtifact/private-recs/params"
)

var starts = []string{"ones", "random"}

func main() {
	// The program runs every attack in a separate copy of itself, started with the
	// first argument "child". Such a copy performs that one attack and exits.
	if len(os.Args) == 7 && os.Args[1] == "child" {
		runChild(os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6])
		return
	}

	// reading the command-line flags
	name := flag.String("matrix", "80x24", "name of a matrix: one listed in Matrices, ml100k or ml100k-40 (see Load)")
	paramsPath := flag.String("params", "params/cheap_params.json", "power-iteration parameters")
	from := flag.Int("from", 30, "smallest exponent e of Λ = 2^e")
	to := flag.Int("to", 90, "largest exponent e of Λ = 2^e")
	repeats := flag.Int("repeats", 5, "runs per exponent and start vector")
	out := flag.String("csv", "", "CSV file for the runs (default attacks/leakageAttack/results/sweep-<matrix>.csv)")
	flag.Parse()

	// rejecting exponents for which Λ = 2^e does not fit in Nudge's 128-bit integers
	if *from < 0 || *to > 127 || *from > *to {
		fmt.Fprintln(os.Stderr, "the exponents must satisfy 0 <= from <= to <= 127")
		os.Exit(2)
	}

	// loading the matrix and its victims by name, and the parameters
	U, victims, err := leakageattack.Load(*name)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	p := params.FromJSON(*paramsPath)

	// running Nudge once without attack to read the honest values h, needed for
	// the exact lowest Λ
	h := leakageattack.HonestRun(U, p)

	// finding the executable file this program is running from, so that it can
	// start copies of itself, one per attack run
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// collecting the results of all victims, written to the CSV file at the end
	var results []leakageattack.Result
	for _, victim := range victims {
		// computing the predicted bounds on Λ for this victim
		bounds := leakageattack.Bounds(U, victim, h, p)

		// collecting this victim's results, one per attack run
		var victimResults []leakageattack.Result
		for e := *from; e <= *to; e++ {
			// starting the progress line for this exponent, completed below
			progress := fmt.Sprintf("2^%d:", e)
			for _, start := range starts {
				leaks := 0
				for r := 0; r < *repeats; r++ {
					// running one attack with Λ = 2^e and this start vector, in a
					// copy of this program, and recording its verdict and the sign of its
					// honest values
					verdict, sign := runOne(self, *name, *paramsPath, victim, e, start)
					victimResults = append(victimResults, leakageattack.Result{Matrix: *name, Victim: victim, Exponent: e, Start: start, Verdict: verdict, HonestSign: sign})

					// counting the runs that revealed the victim's items
					if verdict == leakageattack.Leak {
						leaks++
					}
				}

				// adding to the progress line how many runs with this start vector leaked
				progress += fmt.Sprintf("  %s start %d of %d leaked", start, leaks, *repeats)
			}

			// printing the progress line once both start vectors are done
			fmt.Println(progress)
		}

		// printing this victim's table, and adding its results to those of all victims
		printTable(*name, leakageattack.Ratings(U), bounds, victimResults)
		results = append(results, victimResults...)
	}

	// writing one line per run to the CSV file
	path := *out
	if path == "" {
		path = filepath.Join("attacks", "leakageAttack", "results", "sweep-"+*name+".csv")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := leakageattack.WriteResultsCSV(path, results); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s\n", path)
}

// runChild performs one attack run in a copy of this program started by the
// sweep
func runChild(name, paramsPath, victim, exponent, start string) {
	// reading the run's configuration from the arguments the sweep passed
	row, err1 := strconv.ParseUint(victim, 10, 64)
	e, err2 := strconv.Atoi(exponent)
	if err1 != nil || err2 != nil {
		fmt.Fprintln(os.Stderr, "bad child arguments")
		os.Exit(2)
	}

	// loading the same matrix as the sweep and setting the start vector
	U, _, err := leakageattack.Load(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	p := params.FromJSON(paramsPath)
	p.Start_random = start == "random"

	// running the attack and printing the verdict and the sign of the honest values
	revealed, sign := leakageattack.AttackRun(U, p, row, e)
	fmt.Printf("RESULT %s %s\n", leakageattack.AttackVerdict(revealed, leakageattack.ItemsRatedBy(U, row)), sign)
}

// runOne starts a copy of this program for one attack run and returns its
// verdict and the sign of its honest values. A copy that dies counts as
// OVERFLOW when Nudge stopped because a value to be revealed did not fit in 64
// bits, and as CRASH otherwise, both with an empty sign.
func runOne(self, name, paramsPath string, victim uint64, exponent int, start string) (leakageattack.Verdict, string) {
	cmd := exec.Command(self, "child", name, paramsPath, fmt.Sprint(victim), fmt.Sprint(exponent), start)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	// classifying a copy that died by Nudge's error message
	if err := cmd.Run(); err != nil {
		if strings.Contains(stderr.String(), "does not fit in 64 bits") {
			return leakageattack.Overflow, ""
		}
		return leakageattack.Crash, ""
	}

	// finding the result line among Nudge's progress output
	for _, line := range strings.Split(stdout.String(), "\n") {
		if rest, found := strings.CutPrefix(line, "RESULT "); found {
			if fields := strings.Fields(rest); len(fields) == 2 {
				return leakageattack.Verdict(fields[0]), fields[1]
			}
		}
	}
	return leakageattack.Crash, ""
}

// printTable prints, for one victim, the predicted bounds, the attacker's
// choice of Λ, and for each start vector the exponents e of Λ = 2^e at which
// the runs leaked, gave an all-zero row, or stopped.
func printTable(name string, ratings uint64, bounds leakageattack.VictimBounds, results []leakageattack.Result) {
	choice := bounds.AttackerExponent()
	fmt.Printf("\nvictim user %d of %s, who rated %d items, S = %d ratings\n", bounds.Row, name, len(bounds.RatedItems), ratings)
	fmt.Printf("predicted, in bits: case 1 %.2f, case 2 %.2f, attacker's lowest %.2f, highest %.2f\n",
		bounds.LowestCase1, bounds.LowestCase2, bounds.LowestAttacker, bounds.Highest)
	fmt.Printf("attacker's choice: 2^%d\n", choice)

	for _, start := range starts {
		// counting, for each exponent, the runs and how often each verdict occurred
		total := map[int]int{}
		count := map[int]map[leakageattack.Verdict]int{}
		for _, r := range results {
			if r.Start != start {
				continue
			}
			total[r.Exponent]++
			if count[r.Exponent] == nil {
				count[r.Exponent] = map[leakageattack.Verdict]int{}
			}
			count[r.Exponent][r.Verdict]++
		}

		// collecting the exponents at which every run leaked, some run leaked,
		// some row was all zeros, and some run stopped
		var everyLeak, someLeak, someZero, someStop []int
		for e, n := range total {
			c := count[e]
			if c[leakageattack.Leak] == n {
				everyLeak = append(everyLeak, e)
			}
			if c[leakageattack.Leak] > 0 {
				someLeak = append(someLeak, e)
			}
			if c[leakageattack.Underflow] > 0 {
				someZero = append(someZero, e)
			}
			if c[leakageattack.Overflow]+c[leakageattack.Crash] > 0 {
				someStop = append(someStop, e)
			}
		}

		fmt.Printf("\n%s start, exponents e of Λ = 2^e\n", start)
		fmt.Printf("  every run leaked:   %s\n", ranges(everyLeak))
		fmt.Printf("  some run leaked:    %s\n", ranges(someLeak))
		fmt.Printf("  some row all zeros: %s\n", ranges(someZero))
		fmt.Printf("  some run stopped:   %s\n", ranges(someStop))

		// checking, at the exponents where only some runs leaked, that the runs
		// that did not leak are the ones with negative honest values
		notLeaked, negative := 0, 0
		for _, r := range results {
			c := count[r.Exponent]
			if r.Start != start || c[leakageattack.Leak] == 0 || c[leakageattack.Leak] == total[r.Exponent] {
				continue
			}
			if r.Verdict != leakageattack.Leak {
				notLeaked++
				if r.HonestSign == "negative" {
					negative++
				}
			}
		}
		if notLeaked > 0 {
			fmt.Printf("  where only some runs leaked, %d of the %d runs that did not leak had negative honest values\n", negative, notLeaked)
		}
		if total[choice] > 0 {
			fmt.Printf("  at the attacker's choice 2^%d: %d of %d runs leaked\n", choice, count[choice][leakageattack.Leak], total[choice])
		}
	}
	fmt.Println()
}

// ranges writes a list of exponents as ranges of consecutive ones, such as
// "44-77, 84-90", or "none" for an empty list.
func ranges(es []int) string {
	if len(es) == 0 {
		return "none"
	}
	sort.Ints(es)
	var parts []string
	first := es[0]
	for i := 1; i <= len(es); i++ {
		// closing the current range at the end of the list or at a gap
		if i == len(es) || es[i] != es[i-1]+1 {
			if first == es[i-1] {
				parts = append(parts, fmt.Sprint(first))
			} else {
				parts = append(parts, fmt.Sprintf("%d-%d", first, es[i-1]))
			}
			if i < len(es) {
				first = es[i]
			}
		}
	}
	return strings.Join(parts, ", ")
}
