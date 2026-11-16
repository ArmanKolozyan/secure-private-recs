// In this program, server 0 changes a row of the model that the servers
// compute in training. Nudge stores a real number as an integer with a fixed
// number of fractional bits. A product of two such numbers has twice as many
// fractional bits, so after a multiplication the servers run Trunc, which
// drops the extra ones. The servers compute a row in several steps of power
// iteration, and each step ends with Normalize, which scales the row to
// length 1. Normalize itself ends with a Trunc followed by a Reshare.
//
// Trunc works on each entry x of the row separately. In Nudge's shares,
// servers 1 and 2 both hold the same share of x, which is x + r for a random
// number r. Server 0 holds the other two shares, which add up to minus r, so
// it knows r. Truncating x + r and subtracting the truncated r gives the
// truncated x, up to a carry of 0 or 1 in the last bit. Server 1 truncates
// x + r itself, but only server 0 knows the truncated r. So server 0 acts as
// the dealer, which puts the truncated r into the result without servers 1
// and 2 learning it. For every entry, it sends server 1 a random number m,
// and server 2 the truncated r minus m. Server 1's share of the result is the
// truncated x + r minus m, and server 2's share is minus its number, which is
// m minus the truncated r. The two shares add up to the truncated x + r minus
// the truncated r.
//
// Server 2 cannot check the number it gets. It does not know m, so the
// number looks random to it. If server 0 subtracts an amount from this
// number, server 2's share grows by that amount, and so does the entry. Here
// server 0 subtracts 1 from the number for the entry of a target item, the
// item with the fewest ratings, in the last Trunc of the last step for the
// first row. After this Trunc come only the final Reshare of Normalize and
// the reveal, so the revealed first row is the honest one with 1 added to the
// target item's entry. Any server could make the same change in that Reshare,
// by adding 1 to its own share. This attack does not go through a Reshare, so
// a defense that checks only the Reshares would not stop it.
//
// A user's score for item j is the sum of a[c] * B[c][j] over the rows c,
// where B is the model and a is the user's embedding. The entry a[c] is the
// sum of B[c][j] over the items j the user rated. The first row then adds
// a[0] * 1 more to the target item's score. Every a[0] is positive, since it
// is a sum of entries of the first row, which are all positive. So the target
// item's score rises for every user. But the row is then longer than 1, while
// every row of an honest model has length 1, so a check of the lengths would
// catch this change.
//
// The program trains the model on MovieLens 100K with Nudge's three servers,
// once honestly and once with the attack. For each model it prints in how many
// users' lists the target item appears, and how close the rows are to length 1
// and to being orthogonal to each other.
//
//	make run CMD=./attacks/truncAttack
package main

import (
	"fmt"
	"os"

	"github.com/NudgeArtifact/private-recs/attacks/common"
	"github.com/NudgeArtifact/private-recs/params"
	"github.com/NudgeArtifact/private-recs/protocol"
	"github.com/NudgeArtifact/private-recs/share"
	"github.com/NudgeArtifact/private-recs/uint128"
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

	// choosing the target item, the item with the fewest ratings
	target := common.LeastRated(U, 1)[0]
	fmt.Printf("target item %d, with %d ratings\n", target, common.RatingsPerItem(U)[target])

	// training the model honestly
	fmt.Println("training the model honestly with Nudge's three servers")
	before := common.Report("honest model", U, common.TrainWithServers(U, p), target, top, p.N_decimals)

	// training the model again, while server 0 changes the number it sends
	// server 2 for the target item's entry in the last Trunc for the first row
	fmt.Println("training the model again, while server 0, the dealer in Trunc, adds 1 to the target item's entry of the first row")
	protocol.TruncHook = addOne(target, p.N_iters, p.N_decimals)
	after := common.Report("attacked model", U, common.TrainWithServers(U, p), target, top, p.N_decimals)

	// checking whether the target item is now in more lists
	if after > before {
		fmt.Printf("the attack worked, since the target item is now in %d of the %d lists, while in the honest run it was in %d\n", after, U.NRows(), before)
	} else {
		fmt.Printf("the attack failed, since the target item is in %d of the %d lists, and in the honest run it was in %d\n", after, U.NRows(), before)
	}
}

// This function returns the hook through which server 0 changes the first row
// of the model. It is attached as protocol.TruncHook, which server 0 calls in
// the last Trunc of every Normalize, once for every entry, right before it
// sends the entry's messages to servers 1 and 2. The hook acts only on the
// entry of the item 'target', in the last of the 'steps' steps for the first
// row. It then subtracts 1 from the numbers in the message for server 2,
// which adds 1 to server 2's share of the entry. The share is in Nudge's
// fixed point with 'decimals' fractional bits.
func addOne(target uint64, steps, decimals int) func(int, int, uint64, *share.TruncKey, *share.TruncKey) {
	return func(component, step int, entry uint64, msg1, msg2 *share.TruncKey) {
		// changing only the target item's entry, in the last step for the first row
		if component != 0 || step != steps-1 || entry != target {
			return
		}

		// Subtracting 1, which in Nudge's fixed point is 2^'decimals', from both
		// numbers in server 2's message. The field 'Share' holds the truncated r
		// minus m. When x + r may have wrapped around 2^128, servers 1 and 2
		// compute the result in another way, with the number in the field
		// 'Share2'. Server 2 can tell from x + r which number to use, but
		// server 0 cannot, since it does not know x, so it changes both.
		one := uint128.MakeUint128(0, 1<<decimals)
		msg2.Share.SubInPlace(one)
		msg2.Share2.SubInPlace(one)
	}
}
