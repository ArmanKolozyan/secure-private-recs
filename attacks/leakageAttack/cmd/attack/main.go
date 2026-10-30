// This program tests whether one malicious Nudge server can learn which items a
// chosen user, the victim, rated. It runs Nudge's power iteration on a synthetic
// matrix, in one process that plays all three servers. In the last iteration
// of the first component, one server adds a large integer Λ to its share of the
// victim's entry of the product of the ratings matrix and the current vector
// (see AttackRun). The next step multiplies by the transposed ratings matrix,
// which turns this into an addition on every item the victim rated. For a
// large enough Λ, those items then get the largest coordinates of the first
// model row the servers reveal, so the attacker can read them off.
//
// For each victim of the matrix, the program prints the revealed row, the
// attacker's guess for the victim's items, the items the victim actually
// rated, the sign of the honest values (see AttackRun), and the verdict. Λ is chosen as a power of two: -exponent 50 means
// Λ = 2^50. Without -exponent nothing is added, which gives the baseline: an
// honest run, whose revealed row should not expose the victim's items.
//
//	make run CMD=./attacks/leakageAttack/cmd/attack ARGS="-matrix 80x24 -exponent 50"
package main

import (
	"flag"
	"fmt"
	"os"

	leakageattack "github.com/NudgeArtifact/private-recs/attacks/leakageAttack"
	"github.com/NudgeArtifact/private-recs/params"
)

func main() {
	// reading the command-line flags
	name := flag.String("matrix", "80x24", "name of a matrix: one listed in Matrices, ml100k or ml100k-40 (see Load)")
	paramsPath := flag.String("params", "params/cheap_params.json", "power-iteration parameters")
	exponent := flag.Int("exponent", -1, "inject Λ = 2^exponent, from 0 to 127; -1 means no injection")
	randomStart := flag.Bool("random-start", false, "start power iteration from Nudge's random vector instead of all-ones")
	flag.Parse()

	// rejecting exponents for which Λ = 2^exponent does not fit in Nudge's
	// 128-bit integers
	if *exponent < -1 || *exponent > 127 {
		fmt.Fprintln(os.Stderr, "the exponent must be -1 or between 0 and 127")
		os.Exit(2)
	}

	// loading the matrix and its victims by name
	U, victims, err := leakageattack.Load(*name)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	// loading the parameters and setting the start vector of power iteration
	p := params.FromJSON(*paramsPath)
	p.Start_random = *randomStart

	// naming the start vector and the injection for the printed header
	start := "ones"
	if *randomStart {
		start = "random"
	}
	injection := "no injection"
	if *exponent >= 0 {
		injection = fmt.Sprintf("injection 2^%d", *exponent)
	}

	for _, victim := range victims {
		// running Nudge with the injection aimed at this victim, and taking the
		// first model row the servers reveal
		row, sign := leakageattack.AttackRun(U, p, victim, *exponent)

		// reading the items the victim actually rated, which only the experiment
		// knows, to judge the attacker's guess
		items := leakageattack.ItemsRatedBy(U, victim)

		// printing the revealed row, the attacker's guess for the victim's items
		// and the items the victim actually rated, but only for matrices with at
		// most 40 items, where these lists stay readable
		fmt.Printf("matrix %s, %s start, %s, victim user %d, who rated %d items\n", *name, start, injection, victim, len(items))
		if U.NCols() <= 40 {
			fmt.Printf("  revealed row:     %v\n", row)
			fmt.Printf("  attacker's guess: %v\n", leakageattack.AttackerGuess(row, len(items)))
			fmt.Printf("  items rated:      %v\n", items)
		}

		// printing the sign of the honest values and the verdict
		fmt.Printf("  honest values:    %s\n", sign)
		fmt.Printf("  verdict:          %s\n", leakageattack.AttackVerdict(row, items))
	}
}
