// In this program, server 0 makes the servers accept ratings that are not 0
// or 1. Before training, Nudge's servers check that every entry of the
// ratings matrix U is 0 or 1, since a user could submit any other value. For
// every entry u they compute u * (u - 1), which is 0 exactly when u is 0 or 1,
// multiply it by a random number, and add up the results. Each server ends up
// with a share of this sum, which is 0 for valid ratings and not 0 for the
// invalid ones used here. In Nudge's code, servers 1 and 2 send their shares
// to server 0, which adds the three shares and sends the sum back, and every
// server accepts the ratings when the sum is 0. Servers 1 and 2 know only
// their own shares, so they cannot check the sum that server 0 sends. A
// malicious server 0 sends 0, and all three servers accept invalid ratings. It
// could just as well send a sum that is not 0 for valid ratings, so that the
// servers wrongly reject them.
//
// The program shows three things, with Nudge's three servers, on the ratings
// of MovieLens 100K plus one new user, who gives a single item the rating 256.
//
//  1. With an honest server 0, the check catches the invalid rating, and all
//     three servers reject the ratings.
//  2. With a malicious server 0, which sends 0 as the sum, all three servers
//     accept the same ratings.
//  3. The accepted rating changes the model. The new user's item is the one
//     with the fewest ratings. In every step of power iteration, the servers
//     multiply the row they compute, which has one entry per item, by U and
//     then by the transpose of U. The first gives each user a total, which
//     adds up the row's entries for the items the user rated, each times the
//     user's rating. The second gives each item a new entry, which adds up the
//     totals of the users who rated the item, each times their rating. The
//     new user rated only this item, with 256, so the new user's total is 256
//     times the item's entry, and the item gets 256 times this total back. So
//     the item's entry is multiplied by 256 * 256 in every step. The honest
//     first row also grows in every step, by a factor that depends on all the
//     ratings. If 256 * 256 is the larger factor, the item's entry soon
//     outgrows all others, and Normalize leaves the first row with about 1 on
//     that item and 0 elsewhere. The model keeps one row fewer for the honest ratings, 
// 		 and many users' lists change.
//
// For the third, the program trains the model with and without the new user,
// and prints the first row's entry for the item and in how many users' lists
// the two models differ.
//
//	make run CMD=./attacks/checkAttack
package main

import (
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/NudgeArtifact/private-recs/attacks/common"
	"github.com/NudgeArtifact/private-recs/params"
	"github.com/NudgeArtifact/private-recs/protocol"
	"github.com/NudgeArtifact/private-recs/share"
	"github.com/NudgeArtifact/private-recs/uint128"
)

const (
	top    = 20  // number of items in a list of recommendations
	rating = 256 // the rating the new user gives, where a valid rating is 1
)

func main() {
	// loading MovieLens 100K and the parameters of Nudge's runs on it
	U, err := common.MovieLens(common.MovieLensFile, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	p := params.FromJSON("params/movielens_tiny_params.json")
	fmt.Printf("matrix ml100k, %d users x %d items, K = %d, lists of %d items\n", U.NRows(), U.NCols(), p.K, top)

	// adding the new user, who rates the item with the fewest ratings
	item := common.LeastRated(U, 1)[0]
	withUser := addUser(U, item, rating)
	fmt.Printf("a new user rates item %d, which has %d ratings, with %d\n", item, common.RatingsPerItem(U)[item], rating)

	// running the 0/1 check with an honest server 0
	rejected := check(withUser)
	fmt.Printf("0/1 check with an honest server 0: %s\n", verdicts(rejected))

	// running the 0/1 check again, while server 0 announces 0 as the sum
	protocol.CheckHook = func(sum *uint128.Uint128) { uint128.Clear(sum) }
	accepted := check(withUser)
	fmt.Printf("0/1 check with a malicious server 0: %s\n", verdicts(accepted))

	// training the model on the ratings without and with the new user
	fmt.Println("training the model on the ratings without and with the new user, with Nudge's three servers")
	honest := common.TrainWithServers(U, p)
	attacked := common.TrainWithServers(withUser, p)
	scale := math.Ldexp(1, p.N_decimals)
	fmt.Printf("first row's entry for item %d: %.4f without the new user, %.4f with the new user\n", item, float64(honest[0][item])/scale, float64(attacked[0][item])/scale)

	// comparing the lists of all users but the new one under the two models
	changes := common.CompareLists(common.Recommendations(U, honest, top), common.Recommendations(withUser, attacked, top), U.NRows())
	fmt.Printf("lists that differ between the two models: %d of %d\n", changes.Changed, changes.Users)

	// checking whether the honest check rejected the ratings and the malicious
	// one made all servers accept them
	if rejected == [3]bool{} && accepted == [3]bool{true, true, true} {
		fmt.Printf("the attack worked, since all servers accepted the invalid rating only when server 0 was malicious, and this rating changed %d of the %d lists\n", changes.Changed, changes.Users)
	} else {
		fmt.Println("the attack failed, since the servers did not reject the invalid rating with an honest server 0 and accept it with a malicious one")
	}
}

// This function returns a copy of the ratings matrix 'U' with one more user at
// the end, who gives the item 'item' the rating 'value' and rates nothing
// else.
func addUser(U *share.Matrix[uint64], item, value uint64) *share.Matrix[uint64] {
	withUser := share.MatrixZeros[uint64](U.NRows()+1, U.NCols())
	for i := range U.NRows() {
		for j := range U.NCols() {
			withUser.Set(i, j, U.Get(i, j))
		}
	}
	withUser.Set(U.NRows(), item, &value)
	return withUser
}

// This function runs Nudge's 0/1 check on the ratings matrix 'U' with Nudge's
// three servers. It returns their verdicts, true where a server accepts 'U'.
func check(U *share.Matrix[uint64]) [3]bool {
	var accepted [3]bool
	common.RunServers(U, func(s *protocol.Server) {
		accepted[s.Id] = s.VerifyZeroOneEntries()
	})
	return accepted
}

// This function describes the verdicts of servers 0, 1 and 2 as text.
func verdicts(accepted [3]bool) string {
	words := make([]string, 3)
	for id, ok := range accepted {
		words[id] = fmt.Sprintf("server %d rejects", id)
		if ok {
			words[id] = fmt.Sprintf("server %d accepts", id)
		}
	}
	return strings.Join(words, ", ")
}
