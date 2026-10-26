package experiments

import (
	"sort"

	"github.com/NudgeArtifact/private-recs/share"
)

// Verdict is the outcome of one run of the attack, judged from the model row
// the servers reveal.
type Verdict string

const (
	// LEAK: the attacker's rule picks exactly the items the victim rated
	Leak Verdict = "LEAK"
	// NOLEAK: the row is not all zeros, but the rule picks a different set of items
	NoLeak Verdict = "NOLEAK"
	// UNDERFLOW: the row is all zeros, because the injection was so large that
	// the stored reciprocal of the vector's length rounded to 0
	Underflow Verdict = "UNDERFLOW"
	// OVERFLOW: the run stopped because a value to be revealed did not fit in
	// 64 bits, which happens for injections large enough to wrap around 2^128
	Overflow Verdict = "OVERFLOW"
	// CRASH: the run died for any other reason
	Crash Verdict = "CRASH"
)

// RowAsSigned returns row 'i' of a matrix revealed by Nudge as signed numbers.
// Nudge stores a negative value in a uint64 in two's complement, so the
// conversion is a reinterpretation of the bits.
// Example: row [5, 18446744073709551615] becomes [5, -1].
func RowAsSigned(B *share.Matrix[uint64], i uint64) []int64 {
	row := make([]int64, B.NCols())
	for j := range row {
		row[j] = int64(*B.Get(i, uint64(j)))
	}
	return row
}

// AttackerGuess returns the attacker's guess for the items the victim rated:
// the 'k' coordinates of the revealed row 'row' with the largest absolute
// value, in increasing order. 'k' is the number of items the victim rated,
// which the attacker knows from counting the victim's submissions.
func AttackerGuess(row []int64, k int) []uint64 {
	// ordering the coordinates by absolute value, largest first
	order := make([]int, len(row))
	for j := range order {
		order[j] = j
	}
	sort.SliceStable(order, func(a, b int) bool {
		return abs(row[order[a]]) > abs(row[order[b]])
	})

	// taking the first 'k' and putting them in increasing order
	guess := make([]uint64, k)
	for i, j := range order[:k] {
		guess[i] = uint64(j)
	}
	sort.Slice(guess, func(a, b int) bool { return guess[a] < guess[b] })
	return guess
}

// AttackVerdict decides whether an attack run leaked the victim's items. It
// compares the attacker's guess (see AttackerGuess) with the items the victim
// actually rated. 'row' is the revealed row as signed fixed-point integers, and
// 'items' the items the victim actually rated, which the experiment knows
// because it generated the matrix. The verdict is LEAK when the guess is
// exactly 'items', NOLEAK otherwise, and UNDERFLOW when the row is all zeros.
func AttackVerdict(row []int64, items []uint64) Verdict {
	// checking for the all-zero row
	allZero := true
	for _, x := range row {
		if x != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return Underflow
	}

	// comparing the attacker's guess with the items the victim actually rated
	isRated := make(map[uint64]bool, len(items))
	for _, j := range items {
		isRated[j] = true
	}
	for _, j := range AttackerGuess(row, len(items)) {
		if !isRated[j] {
			return NoLeak
		}
	}
	return Leak
}

// abs returns the absolute value of 'x'.
func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
