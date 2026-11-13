// This file computes the recommendations Nudge serves from a revealed model,
// and compares the lists of two models, typically an honest and an attacked
// one.

package common

import (
	"sort"

	"github.com/NudgeArtifact/private-recs/share"
)

// This function returns the column indices of the items user 'i' rated.
func ItemsRatedBy(U *share.Matrix[uint64], i uint64) []uint64 {
	var items []uint64
	for j := uint64(0); j < U.NCols(); j++ {
		if *U.Get(i, j) != 0 {
			items = append(items, j)
		}
	}
	return items
}

// This function returns the recommendation scores that Nudge's servers send
// to user 'i' for the model 'B', honest or attacked (see Train), one per item.
// Nudge computes the user's embedding as the user's ratings row times the
// transposed model, and the scores as that embedding times the model.
// So the score of item j is the sum, over the rows of the model, of
// (the sum of the row's entries on the items the user rated) * (the row's entry on item j).
func Scores(U *share.Matrix[uint64], B [][]int64, i uint64) []int64 {
	items := ItemsRatedBy(U, i)
	scores := make([]int64, U.NCols())
	for _, row := range B {
		// computing the user's coordinate along this row, which is the sum of
		// the row's entries on the items the user rated
		var a int64
		for _, l := range items {
			a += row[l]
		}

		// adding the row, weighted by that coordinate, to the scores
		for j, b := range row {
			scores[j] += a * b
		}
	}
	return scores
}

// This function returns the 'n' items with the highest 'scores' among those
// user 'i' has not rated, highest first, which are the items Nudge recommends
// to the user. Items with equal scores are ordered by item number, lowest
// first. When the user has rated all but fewer than 'n' items, all the unrated
// ones are returned.
func TopItems(U *share.Matrix[uint64], scores []int64, i uint64, n int) []uint64 {
	// collecting the items the user has not rated
	var items []uint64
	for j := uint64(0); j < U.NCols(); j++ {
		if *U.Get(i, j) == 0 {
			items = append(items, j)
		}
	}

	// Ordering them by score, highest first. The stable sort keeps items with
	// equal scores in the order they were collected, by item number.
	sort.SliceStable(items, func(a, b int) bool { return scores[items[a]] > scores[items[b]] })
	if len(items) > n {
		items = items[:n]
	}
	return items
}

// This function returns every user's list of recommended items for the
// model 'B', honest or attacked. A list holds the 'n' unrated items with the
// highest scores (see Scores and TopItems), highest first.
func Recommendations(U *share.Matrix[uint64], B [][]int64, n int) [][]uint64 {
	lists := make([][]uint64, U.NRows())
	for i := range lists {
		lists[i] = TopItems(U, Scores(U, B, uint64(i)), uint64(i), n)
	}
	return lists
}

// This type summarizes how the recommendation lists of two models differ
// for every user but the victim, whose own list is looked at separately.
// Typically the first model is the honest one and the second an attacked one.
// Two lists count as different when they do not hold the same items, whatever
// the order.
type ListChanges struct {
	Users       int // users compared, which are all but the victim
	Changed     int // users whose list holds different items under the two models
	Replaced    int // items of the first model's lists that the second model's lists do not hold, summed over the users
	MaxReplaced int // the largest such number for a single user
}

// This function computes the ListChanges between the lists 'first' and
// 'second' of two models (see Recommendations), leaving out user 'victim'.
func CompareLists(first, second [][]uint64, victim uint64) ListChanges {
	var changes ListChanges
	for i := range first {
		// skipping the victim, whose list is looked at separately
		if uint64(i) == victim {
			continue
		}
		changes.Users++

		// Counting the items of the user's first list that the second does not
		// hold. Both lists have the same length, so this is also the number of
		// items the second list holds instead.
		left := missing(first[i], second[i])

		// a list counts as changed when at least one item was replaced
		if left > 0 {
			changes.Changed++
		}

		// summing the replaced items over the users, and keeping the largest
		// number for a single user
		changes.Replaced += left
		changes.MaxReplaced = max(changes.MaxReplaced, left)
	}
	return changes
}

// This function returns how many items of 'a' are not in 'b'.
func missing(a, b []uint64) int {
	// collecting the items of 'b' in a set
	in := make(map[uint64]bool, len(b))
	for _, j := range b {
		in[j] = true
	}

	// counting the items of 'a' that are not in that set
	n := 0
	for _, j := range a {
		if !in[j] {
			n++
		}
	}
	return n
}
