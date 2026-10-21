// This program takes a synthetic matrix by name and prints, for the matrix and
// each of its victims, the exact values of the honest computation (the two
// largest eigenvalues and the dominant pattern of the co-rating matrix, the
// honest values on and off the victim's items) and the lowest and highest
// injection that should work. With -csv it also writes them as a table.
//
//	make run CMD=./experiments/cmd/bounds ARGS="-matrix 80x24"
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/NudgeArtifact/private-recs/experiments"
	"github.com/NudgeArtifact/private-recs/params"
)

func main() {
	name := flag.String("matrix", "80x24", "name of a matrix in experiments.Matrices")
	paramsPath := flag.String("params", "params/cheap_params.json", "power-iteration parameters")
	out := flag.String("csv", "", "if set, write the table to this CSV file")
	flag.Parse()

	// looking up the matrix by name and building it
	spec, ok := experiments.Matrices[*name]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown matrix %q\n", *name)
		os.Exit(2)
	}
	p := params.FromJSON(*paramsPath)
	U := experiments.Synthetic(spec)

	// computing the exact values of the honest computation on it
	a := experiments.ExactValues(spec.Name, U, p)

	fmt.Printf("matrix %s: %d users x %d items, S = %d ratings\n", a.Name, a.Users, a.Items, a.S)
	fmt.Printf("  lambda1 = %.3f, lambda2 = %.3f, |q1|_inf = %.4f, lambda1*|q1|_inf = %.3f\n",
		a.Lambda1, a.Lambda2, a.Q1Inf, a.Lambda1*a.Q1Inf)

	// computing and printing the bounds for each victim
	var victims []experiments.VictimBounds
	for _, v := range spec.Victims {
		b := a.Bounds(U, v.Row, p)
		victims = append(victims, b)
		fmt.Printf("victim user %d rated %d items: %v\n", b.Row, len(b.RatedItems), b.RatedItems)
		fmt.Printf("  H_on = %.3f, H_off = %.3f, h_on = %.3f\n", b.HOn, b.HOff, b.HOnMin)
		fmt.Printf("  lowest injection (log2 Lambda): case 1 %.2f, case 2 %.2f, attacker's %.2f; highest %.2f\n",
			b.LowestCase1, b.LowestCase2, b.LowestAttacker, b.Highest)
	}

	// writing the same values as a CSV table when a file was given
	if *out != "" {
		if err := experiments.WriteBoundsCSV(*out, a, victims); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("wrote %s\n", *out)
	}
}
