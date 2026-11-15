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
	"slices"
	"sync"

	"github.com/NudgeArtifact/private-recs/attacks/common"
	"github.com/NudgeArtifact/private-recs/params"
	"github.com/NudgeArtifact/private-recs/protocol"
	"github.com/NudgeArtifact/private-recs/share"
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
	count := ratingsPerItem(U)
	target, popular := 0, 0
	for j := range count {
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
	before := report("honest model", U, train(U, p), target, p.N_decimals)

	// case 1, in which server 0 gives the target item the popular item's entry
	// in every row
	fmt.Println("case 1: in every row, server 0 gives the target item the popular item's entry, and keeps the rows at length 1")
	protocol.RevealHook = changeRows(func(row []float64) { row[target] = row[popular] }, p.N_decimals)
	after1 := report("case 1 model", U, train(U, p), target, p.N_decimals)

	// case 2, in which server 0 gives the target item 5 times the popular
	// item's entry in every row
	fmt.Println("case 2: in every row, server 0 gives the target item 5 times the popular item's entry, and keeps the rows at length 1")
	protocol.RevealHook = changeRows(func(row []float64) { row[target] = 5 * row[popular] }, p.N_decimals)
	after2 := report("case 2 model", U, train(U, p), target, p.N_decimals)

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

// This function trains the model on the ratings matrix 'U' with Nudge's three
// servers, which run in this process and talk to each other over local network
// connections, as in Nudge's own tests. All three servers end up with the
// same model. The function returns server 1's copy,
// one row per component, as signed fixed-point integers.
func train(U *share.Matrix[uint64], p *params.PowerItParams) [][]int64 {
	// splitting the ratings matrix into shares for the three servers
	pool := share.InitPRGPoolFromMatrix(U)
	U0, U1, U2 := share.ShareMatrixRSS(U, pool)
	shares := []*share.Matrix[share.Share128]{U0, U1, U2}

	// silencing the servers while they run, since they print a line for nearly
	// every step
	null, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	stdout := os.Stdout
	os.Stdout = null
	defer func() {
		os.Stdout = stdout
		null.Close()
	}()

	// running the three servers and keeping server 1's model
	var B *share.Matrix[uint64]
	var wg sync.WaitGroup
	wg.Add(3)
	for id := 0; id < 3; id++ {
		go func(id int) {
			defer wg.Done()
			s := protocol.LaunchServerFromMatrix(id, "127.0.0.1", "127.0.0.1", "127.0.0.1", shares[id])
			s.PowerIteration(p, false, true)
			if id == 1 {
				B = s.Item_emb
			}
			s.Teardown()
		}(id)
	}
	wg.Wait()

	// Converting every row to signed numbers. Nudge stores a negative value in
	// a uint64 in two's complement, so the conversion is a reinterpretation of
	// the bits.
	rows := make([][]int64, B.NRows())
	for c := range rows {
		rows[c] = make([]int64, B.NCols())
		for j := range rows[c] {
			rows[c][j] = int64(*B.Get(uint64(c), uint64(j)))
		}
	}
	return rows
}

// This function returns the number of ratings of every item in 'U'.
func ratingsPerItem(U *share.Matrix[uint64]) []int {
	count := make([]int, U.NCols())
	for i := uint64(0); i < U.NRows(); i++ {
		for j := uint64(0); j < U.NCols(); j++ {
			if *U.Get(i, j) != 0 {
				count[j]++
			}
		}
	}
	return count
}

// This function counts the users whose list holds the item 'target' under
// the model 'B', and returns the count. It also prints one line with 'name',
// the count, and how close the rows are to length 1 and to being orthogonal
// to each other (see describeRows).
func report(name string, U *share.Matrix[uint64], B [][]int64, target, decimals int) int {
	// counting the users whose list holds the target item
	n := 0
	for _, list := range common.Recommendations(U, B, top) {
		if slices.Contains(list, uint64(target)) {
			n++
		}
	}
	fmt.Printf("%s: target item in %d of %d lists, %s\n", name, n, U.NRows(), describeRows(B, decimals))
	return n
}

// This function describes the rows of the model 'B', given as signed
// fixed-point integers with 'decimals' fractional bits. An honest model has
// rows of length 1 that are orthogonal to each other, up to rounding, so the
// description shows whether a changed model still looks honest. It returns as
// text the shortest and the longest row length, and the largest inner product
// between two different rows. Two rows are orthogonal when their inner product
// is 0, so a largest inner product near 0 means all rows are orthogonal.
func describeRows(B [][]int64, decimals int) string {
	shortest, longest, largest := math.Inf(1), 0.0, 0.0
	for c := range B {
		for d := c; d < len(B); d++ {
			// computing the inner product of rows 'c' and 'd' in real units, in
			// which a product of two entries has 2 * 'decimals' fractional bits
			dot := 0.0
			for j := range B[c] {
				dot += float64(B[c][j]) * float64(B[d][j])
			}
			dot /= math.Ldexp(1, 2*decimals)

			// A row's inner product with itself is its length squared, which
			// updates the shortest and the longest length. Two different rows
			// update the largest inner product.
			if c == d {
				shortest = math.Min(shortest, math.Sqrt(dot))
				longest = math.Max(longest, math.Sqrt(dot))
			} else {
				largest = math.Max(largest, math.Abs(dot))
			}
		}
	}
	return fmt.Sprintf("row lengths between %.5f and %.5f, largest inner product between two rows %.1e", shortest, longest, largest)
}
