package leakageattack

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
