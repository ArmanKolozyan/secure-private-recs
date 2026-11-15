// In this program, server 0 changes the model that the servers compute in
// training. At the end of every component, the servers reveal the row of the
// model they computed. Nudge's paper mentions that the servers reveal each
// row, and leaves open how they do it. In Nudge's code, server 0 sends the
// sum of its two shares of every entry to servers 1 and 2, and each of them
// adds to it the third share (which server 0 lacks). Server 1 also sends that
// third share to server 0. A malicious server 0 can first wait for
// server 1's message, which gives it the true row, and then add to its own
// messages the difference between the row it wants and the true row.
// Servers 1 and 2 then reconstruct the row server 0 wants.
//
// Here server 0 pushes a target item, the item with the fewest ratings, into
// the users' lists. A user's score for item j is the sum of a[c] * B[c][j]
// over the rows c, where B is the model and a is the user's embedding. The
// entry a[c] is the sum of B[c][j] over the items j the user rated. The
// program tries two cases.
//
//  1. In every row, server 0 gives the target item the entry of a popular
//     item, the item with the most ratings. The program finds this item by
//     counting each item's ratings. A real server 0 holds the ratings only as
//     shares, but it can take the item with the largest entry in the
//     first revealed row. Every user who rated an item adds a positive amount to the
//     item's entry in that row, so a large entry is a good sign that many
//     users rated the item. Changing an entry means the row no longer has
//     length 1 and is no longer orthogonal to the rows revealed before it.
//     In an honest run, the servers compute a row in several steps of power
//     iteration, and every step ends with SetOrthogonal and Normalize, which
//     give the row these two properties. Only after the last step do the
//     servers reveal the row. Server 0 changes the row during the reveal, when
//     no SetOrthogonal or Normalize follows anymore, so it restores both
//     properties itself before it sends its messages.
//  2. As in case 1, but in every row the target item gets 5 times the
//     popular item's entry. A larger factor does
//     not always help. The larger the target item's entry, the more the
//     scaling back to length 1 shrinks the row's other entries, and with them
//     the users' a[c].
//
// Nudge uses the revealed rows when it computes the later rows. SetOrthogonal
// subtracts from each new row its part along every row revealed before. If
// server 0 changed only the first row, by as much as in case 2, this would
// give the second row a negative entry for the target item. Before the
// subtraction, the second row is close to the honest first row, since without
// SetOrthogonal every row would come out as that row.
// The second row has about 0 for the target item, since hardly anyone rated
// it, so subtracting the changed row's large positive entry there makes it
// negative, while the other entries only get smaller. In the users' scores,
// the target item's entries in the first two rows would then cancel. Neither
// case suffers from this, since in both server 0 sets the target item's entry
// in every row.
//
// The program trains the model on MovieLens 100K with Nudge's three servers,
// once honestly and once for each case. For each model it prints in how many
// users' lists the target item appears, and how close the rows are to length 1
// and to being orthogonal to each other.
//
//	make run CMD=./attacks/revealAttack
package main

import (
	"fmt"
	"math"
	"os"

	"github.com/NudgeArtifact/private-recs/attacks/common"
	"github.com/NudgeArtifact/private-recs/params"
	"github.com/NudgeArtifact/private-recs/protocol"
)

const top = 20 // number of items in a list of recommendations

func main() {
	// loading MovieLens 100K and the parameters of Nudge's runs on it
	U, err := common.MovieLens(common.MovieLensFile, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	p := params.FromJSON("params/movielens_tiny_params.json")
	fmt.Printf("matrix ml100k, %d users x %d items, K = %d, lists of %d items\n", U.NRows(), U.NCols(), p.K, top)

	// Choosing the target item, which has the fewest ratings, and the popular
	// item, which has the most. Among items with the same number of ratings,
	// the one with the lowest number is taken.
	count := common.RatingsPerItem(U)
	target, popular := uint64(0), uint64(0)
	for j := range uint64(len(count)) {
		if count[j] < count[target] {
			target = j
		}
		if count[j] > count[popular] {
			popular = j
		}
	}
	fmt.Printf("target item %d, popular item %d, with %d and %d ratings\n", target, popular, count[target], count[popular])

	// training the model honestly
	fmt.Println("training the model honestly with Nudge's three servers")
	before := common.Report("honest model", U, common.TrainWithServers(U, p), target, top, p.N_decimals)

	// case 1, in which server 0 gives the target item the popular item's entry
	// in every row
	fmt.Println("case 1: in every row, server 0 gives the target item the popular item's entry, and keeps the rows at length 1")
	protocol.RevealHook = changeRows(func(row []float64) { row[target] = row[popular] }, p.N_decimals)
	after1 := common.Report("case 1 model", U, common.TrainWithServers(U, p), target, top, p.N_decimals)

	// case 2, in which server 0 gives the target item 5 times the popular
	// item's entry in every row
	fmt.Println("case 2: in every row, server 0 gives the target item 5 times the popular item's entry, and keeps the rows at length 1")
	protocol.RevealHook = changeRows(func(row []float64) { row[target] = 5 * row[popular] }, p.N_decimals)
	after2 := common.Report("case 2 model", U, common.TrainWithServers(U, p), target, top, p.N_decimals)

	// checking whether the target item is now in more lists in both cases
	if min(after1, after2) > before {
		fmt.Printf("the attack worked in both cases, since the target item is now in %d and %d of the %d lists, while in the honest run it was in %d\n", after1, after2, U.NRows(), before)
	} else {
		fmt.Printf("the attack failed in at least one case, since the target item is in %d and %d of the %d lists, and in the honest run it was in %d\n", after1, after2, U.NRows(), before)
	}
}

// This function returns the hook through which server 0 changes the rows that
// servers 1 and 2 reconstruct. It is attached as protocol.RevealHook, so
// server 0 calls it with every true row once it knows it, and the other two
// servers reconstruct the row it returns. The hook first changes the row with
// 'change', which gets the row's entries in real units. It then removes from
// the row its parts along the rows revealed before, and scales the row to
// length 1, as SetOrthogonal and Normalize do for an honest row. The rows are
// Nudge's fixed-point integers with 'decimals' fractional bits.
func changeRows(change func(row []float64), decimals int) func(truth []uint64) []uint64 {
	var revealed [][]float64 // the rows revealed so far, in real units
	return func(truth []uint64) []uint64 {
		// converting the true row to real units
		row := make([]float64, len(truth))
		for j, x := range truth {
			row[j] = float64(int64(x)) / math.Ldexp(1, decimals)
		}

		// changing the row
		change(row)

		// removing from the row its parts along the rows revealed before
		for _, prev := range revealed {
			dot := 0.0
			for j := range row {
				dot += row[j] * prev[j]
			}
			for j := range row {
				row[j] -= dot * prev[j]
			}
		}

		// scaling the row to length 1
		length := 0.0
		for _, x := range row {
			length += x * x
		}
		length = math.Sqrt(length)
		for j := range row {
			row[j] /= length
		}
		revealed = append(revealed, row)

		// converting the row back to Nudge's fixed point
		out := make([]uint64, len(row))
		for j, x := range row {
			out[j] = uint64(int64(math.Round(x * math.Ldexp(1, decimals))))
		}
		return out
	}
}
