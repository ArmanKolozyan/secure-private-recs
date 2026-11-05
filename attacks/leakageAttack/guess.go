package leakageattack

import (
	"math"
	"slices"
	"sort"
)

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

// AttackerGuessWithEarlierRows returns the attacker's guess for the items the
// victim rated when the injection went into a later component. 'rows' are the
// revealed rows up to and including the injected one, which is the last. Nudge
// made the injected row orthogonal to the rows before it, which removed from
// the victim's ratings row its part along those rows, so the injected row is
// the ratings row minus that part, scaled to length 1. Adding the part back
// would give the ratings row, but computing the part needs the ratings row
// itself...
//
// The attacker therefore works in rounds. The first guess is the 'k' largest
// entries of the injected row. Each round assumes the victim rated exactly the
// guessed items. Every earlier row also has length 1, so the part of such a
// ratings row along it is the row times a multiple, and the multiple is the
// sum of the row's own entries over the guessed items. The round then computes
// the rebuilt row: the injected row as Nudge revealed it, scaled back to the
// length it had before Nudge scaled it to 1, plus every earlier row times its
// multiple. If the guess were right, the rebuilt row would be the ratings row.
// The 'k' largest entries of the rebuilt row are the next guess, and the row
// is then thrown away. The rounds stop when the guess no longer changes.
//
// Intuition: assume we have one earlier row, the popularity row, which is
// large on famous movies. Nudge subtracted from every movie a multiple of its
// popularity. A famous movie the victim rated thus lost much of its 1,
// sometimes all of it and more, and then the 'k' largest values miss it. The
// multiple (by which each movie's popularity was multiplied before the
// subtraction) is the total popularity of the victim's movies, so a mostly
// right guess gives nearly the right multiple, and adding it back puts the
// famous rated movie back near 1. Taking the 'k' largest values again now
// gives a better guess. Same logic applies when we have several earlier rows.
//
// TODO: in one case the rounds can go on forever. Each round gives
// every item a number and takes the 'k' items with the largest numbers as the
// next guess. If two items have exactly the same number and only one of them
// fits among the 'k', the code takes the one with the lower item number, and
// the two items can then trade places every round. A possible fix is to stop
// when a guess repeats.
//
// TODO: write out a proof
func AttackerGuessWithEarlierRows(rows [][]int64, k int) []uint64 {
	last := len(rows) - 1
	n := len(rows[last])

	// the injected row and the earlier rows as vectors of length 1
	b := unit(asFloat(rows[last]))
	q := make([][]float64, last)
	for i := range q {
		q[i] = unit(asFloat(rows[i]))
	}

	// the starting guess: the 'k' largest entries of the injected row
	guess := largest(b, k)

	for {
		// the guess as a 0/1 row 'g', with a 1 on each guessed item
		g := make([]float64, n)
		for _, j := range guess {
			g[j] = 1
		}

		// the multiple of each earlier row in the guess, 'c[i]' for row i (the
		// row's entries summed over the guessed items)
		c := make([]float64, last)
		for i := range q {
			c[i] = dot(q[i], g)
		}

		// We calculate here 'r', the length of the row 'g' minus 'c[0]' times
		// row 0, minus 'c[1]' times row 1, and so on for every earlier row.
		// 'g' has 'k' ones, so its length squared is 'k'. The rows have length
		// 1 and are orthogonal to each other, so each subtraction lowers the
		// length squared by the square of 'c[i]' (via Pythagoras).
		// 'r' matters because the injected row is the ratings row minus its
		// own multiples of the rows (which equal 'c[i]' when the guess is
		// right), shrunk to length 1. Before the multiples can be added back
		// below, the shrinking has to be undone, and multiplying by 'r' does
		// that
		left := float64(k)
		for _, ci := range c {
			left -= ci * ci
		}
		r := math.Sqrt(math.Max(left, 0))

		// the rebuilt row: the injected row scaled back by 'r', plus 'c[i]'
		// times each earlier row
		x := make([]float64, n)
		for j := range x {
			x[j] = r * b[j]
			for i := range q {
				x[j] += c[i] * q[i][j]
			}
		}

		// the 'k' largest entries of the rebuilt row are the next guess
		next := largest(x, k)

		// stopping when the guess no longer changes
		if slices.Equal(next, guess) {
			break
		}
		guess = next
	}
	return guess
}

// asFloat converts the fixed-point row 'row' from Nudge's integers to the
// floating-point numbers that AttackerGuessWithEarlierRows computes with.
// Nudge stores a number as the integer number times 2^N_decimals. asFloat does
// not divide by that factor, so the row it returns is 2^N_decimals times too
// large. That does not matter, because the callers pass the row through the
// 'unit' function, which scales it to length 1 and so removes any common
// factor.
func asFloat(row []int64) []float64 {
	v := make([]float64, len(row))
	for j, x := range row {
		v[j] = float64(x)
	}
	return v
}

// largest returns the indices of the 'k' largest entries of 'x', in increasing
// order. Among equal entries the lower index comes first.
func largest(x []float64, k int) []uint64 {
	order := make([]int, len(x))
	for j := range order {
		order[j] = j
	}
	sort.SliceStable(order, func(a, b int) bool {
		return x[order[a]] > x[order[b]]
	})
	top := make([]uint64, k)
	for i, j := range order[:k] {
		top[i] = uint64(j)
	}
	sort.Slice(top, func(a, b int) bool { return top[a] < top[b] })
	return top
}

// abs returns the absolute value of 'x'.
func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
