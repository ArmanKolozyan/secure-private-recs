package experiments

import (
	"encoding/csv"
	"fmt"
	"os"
)

// Run is one line of the table with one line per run of the attack.
type Run struct {
	Matrix   string  // name of the matrix, as in Matrices
	Victim   uint64  // the victim's row
	Exponent int     // the injection is Λ = 2^Exponent, and -1 means no injection (an honest run)
	Start    string  // "ones" or "random", Nudge's two ways of choosing the start vector of power iteration
	Verdict  Verdict // outcome of the run, see AttackVerdict
}

// RunHeader is the column list of that table.
var RunHeader = []string{"matrix", "victim", "exponent", "start", "verdict"}

// Record returns the run as one CSV line, in the order of RunHeader.
func (r Run) Record() []string {
	return []string{r.Matrix, fmt.Sprint(r.Victim), fmt.Sprint(r.Exponent), r.Start, string(r.Verdict)}
}

// WriteRunsCSV writes the table of runs to a file.
func WriteRunsCSV(path string, runs []Run) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write(RunHeader); err != nil {
		return err
	}
	for _, r := range runs {
		if err := w.Write(r.Record()); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}
