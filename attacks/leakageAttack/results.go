package leakageattack

import (
	"encoding/csv"
	"fmt"
	"os"
)

// Result is the outcome of one run of the attack, which makes one line of the
// results table.
type Result struct {
	Matrix     string  // name of the matrix, as in Matrices
	Victim     uint64  // the victim's row
	Exponent   int     // the injection is Λ = 2^Exponent, and -1 means no injection (an honest run)
	Start      string  // "ones" or "random", Nudge's two ways of choosing the start vector of power iteration
	Verdict    Verdict // outcome of the run, see AttackVerdict
	HonestSign string  // sign of the honest values in the run, see AttackRun, and "" when the run stopped
}

// ResultHeader is the column list of the results table.
var ResultHeader = []string{"matrix", "victim", "exponent", "start", "verdict", "honest_sign"}

// Record returns the result as one CSV line, in the order of ResultHeader.
func (r Result) Record() []string {
	return []string{r.Matrix, fmt.Sprint(r.Victim), fmt.Sprint(r.Exponent), r.Start, string(r.Verdict), r.HonestSign}
}

// WriteResultsCSV writes the results table to a file.
func WriteResultsCSV(path string, results []Result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write(ResultHeader); err != nil {
		return err
	}
	for _, r := range results {
		if err := w.Write(r.Record()); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}
