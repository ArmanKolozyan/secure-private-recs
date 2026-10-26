package leakageattack

import "sort"

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

// abs returns the absolute value of 'x'.
func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
