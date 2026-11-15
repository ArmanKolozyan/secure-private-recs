// In this program, one server changes a row of the model that the servers
// compute in training. The servers compute a row in several steps of power
// iteration. Every step multiplies the row by the ratings matrix U, which has
// one row per user and one column per item, and then by the transpose of U.
// It then runs SetOrthogonal, and ends with Normalize, which scales the row to
// length 1. Normalize itself ends with a Reshare, in which every server sends
// its share of the row, masked, to one other server. The receiver cannot check
// what it gets, since a correct share looks random, so a server that adds an
// amount to its share adds that amount to the row. Any of the three servers can do this,
// since the row is the sum of their three shares.
//
// Here server 1 adds 1 to the entry of a target item, the item with the
// fewest ratings, in the first row. A user's score for item j is the sum of
// a[c] * B[c][j] over the rows c, where B is the model and a is the user's
// embedding. The entry a[c] is the sum of B[c][j] over the items j the user
// rated. The first row then adds a[0] * 1 more to the target item's score.
// Every a[0] is positive, since it is a sum of entries of the first row, which
// are all positive. So the target item's score rises for every user. But the
// row is then longer than 1, while every row of an honest model has length 1,
// so a check of the lengths would catch this change.
//
// The later rows do not undo this change. When Nudge computes the second row,
// SetOrthogonal subtracts from it its part along the first row. Since the
// first row still holds the whole honest first row, this removes the honest
// first row from the second row completely, and leaves a negative entry on the
// target item. The multiplications of the next step clear that entry, since
// hardly anyone rated the target item, and with no honest first row left,
// SetOrthogonal subtracts nothing more. So the second row comes out as in an
// honest run.
//
// Two other variants of this attack are possible. They change a share in an
// earlier Reshare of the last step, the one right after the multiplication by
// the transpose of U. SetOrthogonal and Normalize still run after it, so the
// changed row keeps length 1 and stays orthogonal to the earlier rows, and
// unlike here a check of the rows would not catch it.
//   - In the first variant, a server adds a small amount to the target item's
//     entry, which pushes the target item into some users' lists.
//   - In the second variant, a server picks the row it wants the model to have
//     instead of the honest one, of length 1 and orthogonal to the earlier
//     rows, and adds a huge multiple of it to its share, for example a million
//     times the wanted row. The honest numbers are tiny next to the added ones,
//     so the row now consists almost only of the wanted row, and Normalize,
//     which scales it back to length 1, gives the wanted row. Doing this for
//     every row, each time with a new wanted row, the server decides the whole
//     model without ever seeing a true row.
//
// The program trains the model on MovieLens 100K with Nudge's three servers,
// once honestly and once with the attack. For each model it prints in how many
// users' lists the target item appears, and how close the rows are to length 1
// and to being orthogonal to each other.
//
//	make run CMD=./attacks/reshareAttack
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

	// training the model again, while server 1 adds 1 to the target item's
	// entry of the first row
	fmt.Println("training the model again, while server 1 adds 1 to the target item's entry of the first row")
	protocol.NormalizeHook = addOne(target, p.N_iters, p.N_decimals)
	after := common.Report("attacked model", U, common.TrainWithServers(U, p), target, top, p.N_decimals)

	// checking whether the target item is now in more lists
	if after > before {
		fmt.Printf("the attack worked, since the target item is now in %d of the %d lists, while in the honest run it was in %d\n", after, U.NRows(), before)
	} else {
		fmt.Printf("the attack failed, since the target item is in %d of the %d lists, and in the honest run it was in %d\n", after, U.NRows(), before)
	}
}

// This function returns the hook through which server 1 changes the first row
// of the model. It is attached as protocol.NormalizeHook, which every server
// calls right before the last Reshare of every Normalize. The hook acts only
// when server 1 calls it in the last of the 'steps' steps for the first row.
// It then adds 1 to server 1's share of the entry of the item 'target'. The
// share is in Nudge's fixed point with 'decimals' fractional bits.
func addOne(target uint64, steps, decimals int) func(int, int, int, *share.Matrix[uint128.Uint128]) {
	return func(server, component, step int, row *share.Matrix[uint128.Uint128]) {
		// changing only server 1's share, in the last step for the first row
		if server != 1 || component != 0 || step != steps-1 {
			return
		}

		// adding 1 to the target item's entry, which in Nudge's fixed point is
		// 2^'decimals'
		row.Data[target].AddInPlace(uint128.MakeUint128(0, 1<<decimals))
	}
}
