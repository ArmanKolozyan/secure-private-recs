// This program tests whether the attack shows in the recommendations. In the
// attack, one malicious Nudge server adds a large integer Λ to its share of the
// victim's entry of the product of the ratings matrix and the current vector,
// in the last iteration of the first component (see AttackRun), which makes
// the first model row the servers reveal expose the items the victim rated.
// The later rows are computed at right angles to that row, so the whole model
// changes, and with it every user's recommendations.
//
// The program runs Nudge honestly twice and, for each victim of the matrix,
// once with the injection Λ = 2^exponent, computing all components of the
// model (see Model). From each revealed model it computes every user's list of
// the -top items with the highest scores among the items the user has not
// rated, as Nudge serves them (see Scores and TopItems). It then prints, for
// every user but the victim, how the lists of the two honest runs differ,
// which is the difference Nudge's own randomness makes, and how the lists of
// the attacked run differ from those of the first honest run. The victim's
// own lists are printed separately. With them comes the number of the
// victim's unrated items whose score is exactly 0. In exact arithmetic the
// attack would give all of them score 0, because the model's rows are at
// right angles to the victim's ratings row except for the first, which lies
// along it and has nothing on the unrated items. Without -exponent, only the
// two honest runs are compared.
//
//	make run CMD=./attacks/leakageAttack/cmd/recs ARGS="-matrix ml100k -params params/movielens_tiny_params.json -exponent 68"
package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"slices"
	"strings"

	leakageattack "github.com/NudgeArtifact/private-recs/attacks/leakageAttack"
	"github.com/NudgeArtifact/private-recs/params"
	"github.com/NudgeArtifact/private-recs/share"
)

func main() {
	// reading the command-line flags
	name := flag.String("matrix", "80x24", "name of a matrix: one listed in Matrices, ml100k or ml100k-40 (see Load)")
	paramsPath := flag.String("params", "params/cheap_params.json", "power-iteration parameters")
	exponent := flag.Int("exponent", -1, "inject Λ = 2^exponent, from 0 to 127; -1 means no injection")
	top := flag.Int("top", 20, "number of items in every user's list of recommendations")
	randomStart := flag.Bool("random-start", false, "start power iteration from Nudge's random vector instead of all-ones")
	flag.Parse()

	// rejecting exponents for which Λ = 2^exponent does not fit in Nudge's
	// 128-bit integers, and empty lists
	if *exponent < -1 || *exponent > 127 {
		fmt.Fprintln(os.Stderr, "the exponent must be -1 or between 0 and 127")
		os.Exit(2)
	}
	if *top < 1 {
		fmt.Fprintln(os.Stderr, "the lists must hold at least one item")
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
	start := "ones"
	if *randomStart {
		start = "random"
	}

	// running Nudge honestly twice, to see how much Nudge's own randomness
	// changes the lists, and computing every user's list from each model
	honest := leakageattack.Model(U, p, 0, -1)
	again := leakageattack.Model(U, p, 0, -1)
	honestLists := leakageattack.Recommendations(U, honest, *top)
	againLists := leakageattack.Recommendations(U, again, *top)

	// printing the setting, whether the two honest models differ at all
	fmt.Printf("matrix %s, %d users x %d items, K = %d, %s start, lists of %d items\n", *name, U.NRows(), U.NCols(), p.K, start, *top)
	if sameModel(honest, again) {
		fmt.Println("the two honest models are identical")
	} else {
		fmt.Println("the two honest models differ")
	}
	fmt.Printf("honest model, row lengths: %s\n", rowLengths(honest, p.N_decimals))

	// attacking each victim of the matrix in turn
	for _, victim := range victims {
		// the items the victim rated, which the verdict on the first row needs
		items := leakageattack.ItemsRatedBy(U, victim)
		fmt.Printf("\nvictim user %d, who rated %d items\n", victim, len(items))

		// comparing the other users' lists between the two honest runs
		printChanges("honest run vs honest run", leakageattack.CompareLists(honestLists, againLists, victim))

		// printing the victim's honest list
		fmt.Printf("  victim's honest list:   %v\n", honestLists[victim])
		printZeroScores(U, honest, victim)

		// without an injection there is no attacked run to compare with
		if *exponent < 0 {
			continue
		}

		// running Nudge with the injection aimed at this victim, and checking
		// on the first revealed row that the attack worked
		attacked := leakageattack.Model(U, p, victim, *exponent)
		fmt.Printf("  injection 2^%d, verdict on the first row: %s\n", *exponent, leakageattack.AttackVerdict(attacked[0], items))
		fmt.Printf("  attacked model, row lengths: %s\n", rowLengths(attacked, p.N_decimals))

		// comparing the other users' lists between the honest and the attacked run
		attackedLists := leakageattack.Recommendations(U, attacked, *top)
		printChanges("honest run vs attacked run", leakageattack.CompareLists(honestLists, attackedLists, victim))

		// printing the victim's attacked list, how much of the honest list it
		// keeps, and how many of the victim's unrated items now score 0
		kept := 0
		for _, j := range attackedLists[victim] {
			if slices.Contains(honestLists[victim], j) {
				kept++
			}
		}
		fmt.Printf("  victim's attacked list: %v\n", attackedLists[victim])
		fmt.Printf("    items kept from the honest list: %d of %d\n", kept, len(honestLists[victim]))
		printZeroScores(U, attacked, victim)
	}
}

// sameModel reports whether two revealed models hold the same values.
func sameModel(a, b [][]int64) bool {
	if len(a) != len(b) {
		return false
	}
	for c := range a {
		if !slices.Equal(a[c], b[c]) {
			return false
		}
	}
	return true
}

// printChanges prints one line with the changes between two sets of lists
// for the users other than the victim (see ListChanges).
func printChanges(what string, changes leakageattack.ListChanges) {
	fmt.Printf("  other %d users, %s: %d lists changed, %.2f items replaced per user on average, at most %d\n",
		changes.Users, what, changes.Changed, float64(changes.Replaced)/float64(changes.Users), changes.MaxReplaced)
}

// rowLengths writes the lengths of the rows of the model 'B', whose entries
// are fixed-point integers with 'decimals' fractional bits. Nudge is meant to
// normalize every row to length 1, but it does so with rounded fixed-point
// arithmetic, and a row that comes out shorter than 1 weighs less in the
// scores. The lengths are printed to check that this did not happen.
func rowLengths(B [][]int64, decimals int) string {
	var parts []string
	for _, row := range B {
		s := 0.0
		for _, x := range row {
			y := float64(x) / math.Ldexp(1, decimals)
			s += y * y
		}
		parts = append(parts, fmt.Sprintf("%.3f", math.Sqrt(s)))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

// printZeroScores prints how many of the items the victim has not rated get
// the score 0 under the model 'B'.
func printZeroScores(U *share.Matrix[uint64], B [][]int64, victim uint64) {
	scores := leakageattack.Scores(U, B, victim)
	unrated, zero := 0, 0
	for j := uint64(0); j < U.NCols(); j++ {
		if *U.Get(victim, j) != 0 {
			continue
		}
		unrated++
		if scores[j] == 0 {
			zero++
		}
	}
	fmt.Printf("    victim's unrated items with score 0: %d of %d\n", zero, unrated)
}
