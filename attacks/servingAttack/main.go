// This program tests whether one malicious Nudge server can decide what a
// user is recommended. To serve recommendations, each of the three servers
// sends the user its share of the user's scores, one score per item, and the
// user adds up the three shares. The user cannot check a share, so a server
// that adds an amount to its share of an item's score adds that amount to the
// user's score for the item. The malicious server adds a large amount to its
// share of the scores of the items it chose, larger for the items it wants
// higher.
//
// This program computes Nudge's model honestly on MovieLens 100K (training,
// run inside this process), starts Nudge's three recommendation servers with
// the model and the users' embeddings (serving), and fetches the scores of
// one user, the victim, with Nudge's client, once from honest servers and once
// while server 1 is malicious. It prints the chosen list, the victim's two
// lists, and whether the attacked list is now exactly the chosen list.
//
// Nudge prints a line for every connection and every power-iteration step,
// which the command below filters out.
//
//	make run CMD=./attacks/servingAttack 2>&1 | grep -vE "Handshake|TLS server|Iter|took|building|Starting|Multiplied|Recovered|Returing"
package main

import (
	"fmt"
	"os"
	"slices"

	"github.com/NudgeArtifact/private-recs/attacks/common"
	"github.com/NudgeArtifact/private-recs/params"
	"github.com/NudgeArtifact/private-recs/protocol"
	"github.com/NudgeArtifact/private-recs/share"
	"github.com/NudgeArtifact/private-recs/uint128"
)

const (
	victim = 0  // the user whose list the malicious server decides
	top    = 20 // number of items in a list of recommendations
)

func main() {
	// loading MovieLens 100K and the parameters of Nudge's runs on it
	U, err := common.MovieLens(common.MovieLensFile, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	p := params.FromJSON("params/movielens_tiny_params.json")
	fmt.Printf("matrix ml100k, %d users x %d items, K = %d, lists of %d items, victim user %d\n", U.NRows(), U.NCols(), p.K, top, victim)

	// Training the model honestly. Only the model is needed from this step,
	// so the three servers' computation runs inside this process and no real
	// servers are started.
	fmt.Println("training the model honestly")
	B := common.Train(U, p)

	// Starting Nudge's three recommendation servers with the model and every
	// user's embedding. They answer the users' requests for recommendations.
	addrs := serve(U, B)

	// Choosing the 'top' items the malicious server puts in the victim's list.
	// We choose the least-rated items, which honest Nudge recommends to nobody.
	fmt.Println("choosing the least-rated items, which server 1 will put in the victim's list")
	chosen := common.LeastRated(U, top)
	fmt.Printf("chosen list:            %v\n", chosen)

	// fetching the victim's list from honest servers
	fmt.Println("fetching the victim's list from the honest servers")
	honest := list(U, addrs, victim)
	fmt.Printf("victim's honest list:   %v\n", honest)

	// attaching the attack, in which server 1 adds a large amount to its share
	// of each chosen item's score when it serves the victim
	fmt.Println("making server 1 malicious")
	protocol.ServingHook = push(chosen, p.N_decimals)

	// fetching the victim's list again
	fmt.Println("fetching the victim's list again")
	attacked := list(U, addrs, victim)
	fmt.Printf("victim's attacked list: %v\n", attacked)

	// counting the chosen items that were already in the victim's honest list
	before := 0
	for _, j := range chosen {
		if slices.Contains(honest, j) {
			before++
		}
	}

	// checking whether the victim's list is now exactly the chosen list
	if slices.Equal(attacked, chosen) {
		fmt.Printf("the attack worked, since the victim's list is now exactly the list chosen by the server, while in the honest run it held %d of these %d items\n", before, len(chosen))
	} else {
		fmt.Println("the attack failed, since the victim's list is not the list chosen by the server")
	}
}

// This function returns the hook through which server 1 changes its answers.
// The hook is attached as protocol.ServingHook, and each server calls it right
// before it sends a user its share of the user's scores. When server 1
// answers the victim, whom it recognizes by the user id in the request, the
// hook adds a large amount to server 1's share of the score of every chosen
// item. The first of the 20 chosen items gets 20 * 100, the second 19 * 100,
// and so on, down to 1 * 100 for the last. Honest scores on MovieLens 100K lie
// between -0.96 and 2.02, so the chosen items end up far above all other
// items. Any of the three servers could do the same, since the user adds up
// all three shares.
// 'chosen' holds the items that server 1 puts in the victim's list, as item
// numbers (columns of the ratings matrix), from the top of the list down.
// 'decimals' is the number of fractional bits of Nudge's fixed point.
func push(chosen []uint64, decimals int) func(int, uint64, *share.Matrix[uint128.Uint128]) {
	return func(server int, user uint64, scores *share.Matrix[uint128.Uint128]) {
		// changing only server 1's answer to the victim
		if server != 1 || user != victim {
			return
		}

		// going through the chosen items, with 'r' the item's position in the
		// victim's list (0 at the top) and 'j' its item number
		for r, j := range chosen {
			// computing the amount for this item
			amount := uint64(len(chosen)-r) * 100

			// adding the amount in Nudge's fixed point, in which the scores have
			// 2 * 'decimals' fractional bits
			scores.Data[j].AddInPlace(uint128.MakeUint128(0, amount<<(2*decimals)))
		}
	}
}

// This function starts Nudge's three recommendation servers for the model 'B'
// (one row per component, as signed fixed-point integers) and the ratings
// matrix 'U', and returns their addresses. Each server gets the model and its
// share of every user's embedding, which is the user's ratings row times the
// transposed model. Nudge's servers compute these shares themselves at the end
// of training. Here they are made from the embeddings computed in the clear,
// which gives shares of the same values.
func serve(U *share.Matrix[uint64], B [][]int64) [3]string {
	K := uint64(len(B)) // the number of components

	// storing B^T, which has one row per item, because Nudge's recommendation
	// servers store the model in that form ('B' has one row per component)
	items := share.MatrixZeros[uint64](U.NCols(), K)
	for c := range B {
		for j, x := range B[c] {
			v := uint64(x)
			items.Set(uint64(j), uint64(c), &v)
		}
	}

	// Computing every user's embedding a = u * B^T, where u is the user's 0/1
	// ratings row, and splitting it into shares for the three servers. The
	// embedding describes the user's taste with one number per row of the
	// model, and the servers compute the user's scores from it as a * B (i.e.,
	// summing a[c] * B[c][j] over the rows c gives the score of item j).
	pool := share.InitPRGPoolFromMatrix(items)
	shares := make([][]share.Matrix[share.Share128], 3)
	for i := uint64(0); i < U.NRows(); i++ {
		rated := common.ItemsRatedBy(U, i)
		a := share.MatrixZeros[uint64](K, 1)
		for c := range B {
			// computing entry c of a, which is the sum of B[c][j] over the
			// items j the user rated, since u holds a 1 for them and a 0 for
			// all others
			var entry int64
			for _, j := range rated {
				entry += B[c][j]
			}
			v := uint64(entry)
			a.Set(uint64(c), 0, &v)
		}
		s0, s1, s2 := share.ShareMatrixRSS(a, pool)
		shares[0] = append(shares[0], *s0)
		shares[1] = append(shares[1], *s1)
		shares[2] = append(shares[2], *s2)
	}

	// starting the servers, which listen until the program ends
	for id := 0; id < 3; id++ {
		protocol.LaunchRecServer(id, U.NRows(), U.NCols(), false, shares[id], []share.Matrix[uint64]{*items})
	}
	return [3]string{protocol.LocalAddr(protocol.ServerPort0), protocol.LocalAddr(protocol.ServerPort1), protocol.LocalAddr(protocol.ServerPort2)}
}

// This function fetches the scores of user 'i' with Nudge's client, which
// asks the three servers at 'addrs' and adds up the three shares it receives.
// It returns the user's list, which holds the 'top' items with the highest
// scores among those the user has not rated, highest first (see
// common.TopItems).
func list(U *share.Matrix[uint64], addrs [3]string, i uint64) []uint64 {
	c := protocol.LaunchRecClient(U.NRows(), 1, U.NCols(), i, addrs[0], addrs[1], addrs[2])
	res, _, _, _, _, _, _ := c.FetchRecsWithoutClustering()

	// closing the connections, which the client keeps open otherwise
	for _, conn := range c.Conns {
		conn.Close()
	}

	// reading the scores the client added up, one per item, as signed
	// fixed-point integers
	scores := make([]int64, U.NCols())
	for j := range scores {
		scores[j] = int64(*res[0].Get(uint64(j), 0))
	}

	// returning the 'top' items with the highest scores among those the user
	// has not rated, highest first, which are the items Nudge recommends
	return common.TopItems(U, scores, i, top)
}
