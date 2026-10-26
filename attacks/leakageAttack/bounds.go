package leakageattack

import (
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"strconv"

	"github.com/NudgeArtifact/private-recs/params"
	"github.com/NudgeArtifact/private-recs/share"
)

// Exact holds the largest eigenvalue of the co-rating matrix of the ratings
// matrix 'U' and the largest coordinate of its dominant eigenvector, computed
// here from the plaintext matrix. Nudge's power iteration only approximates
// the dominant eigenvector and does not output the eigenvalue.
//
// These values are reported for two comparisons:
//   - HOn + HOff versus 2 * Lambda1 * Q1Inf. The first is what the injection
//     must exceed to work whatever the signs of the honest values. The second
//     estimates the same from the eigenvalue and eigenvector alone, since every
//     honest value is about Lambda1 times a coordinate of the dominant
//     eigenvector. The comparison shows how good that estimate is.
//   - Lambda1 * Q1Inf versus S. The first is about the largest honest value.
//     The attacker cannot compute it without the matrix, so LowestAttacker
//     uses S instead, which is always at least as large. Their ratio is the
//     factor by which the attacker's lower bound is larger.
type Exact struct {
	Name    string
	Users   uint64
	Items   uint64
	S       uint64  // total number of ratings
	Lambda1 float64 // largest eigenvalue of the co-rating matrix M = UᵀU
	Q1Inf   float64 // largest coordinate, in absolute value, of the eigenvector of M for Lambda1 (length 1)
}

// VictimBounds holds, for one victim, the honest values (entries of the vector
// h that enters normalization in the last iteration of an honest run, see
// HonestRun) on the items the victim rated and on the other items, and the
// bounds on the
// integer Λ that the attacker adds. Since these bounds range over many
// powers of two, each is given as the exponent of two (i.e., log2(Λ)): a bound of
// 45.84 means Λ = 2^45.84. A lower bound of -Inf holds for every positive Λ.
// The bounds involve two settings of Nudge's parameter files (params/*.json):
// N_decimals, the number of fractional bits of Nudge's fixed-point numbers
// (every real value 'x' is stored as the integer x * 2^N_decimals), and
// Norm_decimals, the number of fractional bits of the stored reciprocal of a
// vector's length. With the default N_decimals = 20 and Norm_decimals = 40,
// the factor 2^(2 * N_decimals) below is 2^40 and 2^(Norm_decimals + 2 * N_decimals)
// is 2^80.
type VictimBounds struct {
	Row            uint64
	RatedItems     []uint64 // the items the victim rated (column indices)
	HOn            float64  // largest honest value (absolute) on the victim's items
	HOff           float64  // largest honest value (absolute) on the other items
	HOnMin         float64  // smallest honest value (absolute) on the victim's items
	LowestCase1    float64  // if all honest values are >= 0, the attack works for Λ > 2^(2 * N_decimals) * (HOff - HOnMin). NaN when some honest value is negative, since the bound then does not apply
	LowestCase2    float64  // whatever their signs, it works for Λ > 2^(2 * N_decimals) * (HOn + HOff)
	LowestAttacker float64  // knowing only the total number of ratings S, it works for Λ > 2^(2 * N_decimals) * 2S
	Highest        float64  // beyond Λ = 2^(Norm_decimals + 2 * N_decimals) / sqrt(number of items the victim rated), the stored reciprocal of the vector's length rounds to 0 and the revealed row is all zeros
}

// ExactValues computes the Exact values (see the struct above) for the matrix 'U'.
func ExactValues(name string, U *share.Matrix[uint64]) *Exact {
	n := int(U.NCols())
	a := &Exact{Name: name, Users: U.NRows(), Items: U.NCols(), S: Ratings(U)}

	// building the co-rating matrix
	M := coRating(U)

	// finding the largest eigenvalue and its eigenvector
	lambda1, q1 := topEigen(M, n)
	a.Lambda1 = lambda1
	for _, q := range q1 {
		a.Q1Inf = math.Max(a.Q1Inf, math.Abs(q))
	}
	return a
}

// Bounds computes, for the victim in row 'row', the honest values on and off
// the victim's items, taken from 'h' (see HonestRun), and the bounds on the
// injection.
func (a *Exact) Bounds(U *share.Matrix[uint64], row uint64, h []float64, p *params.PowerItParams) VictimBounds {
	b := VictimBounds{Row: row, RatedItems: ItemsRatedBy(U, row), HOnMin: math.Inf(1)}
	rated := make([]bool, a.Items)
	for _, j := range b.RatedItems {
		rated[j] = true
	}
	// taking the largest and smallest honest value on the victim's items, and the largest on the others
	for j, hj := range h {
		x := math.Abs(hj)
		if rated[j] {
			b.HOn = math.Max(b.HOn, x)
			b.HOnMin = math.Min(b.HOnMin, x)
		} else {
			b.HOff = math.Max(b.HOff, x)
		}
	}
	// The injection is added where values carry two multiplications' worth of
	// fractional bits, so an integer Λ is worth Λ / 2^(2 * N_decimals) in real
	// units. A real bound 'a' therefore translates to log2(Λ) = 2 * N_decimals + log2(a).
	scale := float64(2 * p.N_decimals)
	// checking that every honest value is at least 0, which LowestCase1 assumes
	allNonNegative := true
	for _, hj := range h {
		if hj < 0 {
			allNonNegative = false
			break
		}
	}
	b.LowestCase1 = math.NaN()
	if allNonNegative {
		b.LowestCase1 = scale + log2(b.HOff-b.HOnMin)
	}
	b.LowestCase2 = scale + log2(b.HOn+b.HOff)
	b.LowestAttacker = scale + log2(2*float64(a.S))
	b.Highest = float64(p.Norm_decimals+2*p.N_decimals) - 0.5*math.Log2(float64(len(b.RatedItems)))
	return b
}

// AttackerExponent returns the exponent e of the attacker's choice Λ = 2^e: the
// middle, in bits, of the range from LowestAttacker to Highest, rounded to an
// integer. The attacker can compute it, since both ends depend only on the
// total number of ratings and on how many items the victim rated.
func (b VictimBounds) AttackerExponent() int {
	return int(math.Round((b.LowestAttacker + b.Highest) / 2))
}

// log2 returns the base-2 logarithm of 'x', and -Inf for x <= 0 (used for
// bounds that hold for every positive injection).
func log2(x float64) float64 {
	if x <= 0 {
		return math.Inf(-1)
	}
	return math.Log2(x)
}

// BoundsHeader is the column list of the table with one line per matrix and victim.
var BoundsHeader = []string{"matrix", "m", "n", "S", "victim", "k",
	"lambda1", "q1_inf", "H_on", "H_off", "h_on",
	"lowest_case1_bits", "lowest_case2_bits", "lowest_attacker_bits", "highest_bits"}

// BoundsRecord is one line of that table.
func BoundsRecord(a *Exact, b VictimBounds) []string {
	f := func(x float64) string { return strconv.FormatFloat(x, 'f', 4, 64) }
	return []string{a.Name, fmt.Sprint(a.Users), fmt.Sprint(a.Items), fmt.Sprint(a.S),
		fmt.Sprint(b.Row), fmt.Sprint(len(b.RatedItems)),
		f(a.Lambda1), f(a.Q1Inf), f(b.HOn), f(b.HOff), f(b.HOnMin),
		f(b.LowestCase1), f(b.LowestCase2), f(b.LowestAttacker), f(b.Highest)}
}

// WriteBoundsCSV writes the table to a file for one matrix and its victims.
func WriteBoundsCSV(path string, a *Exact, victims []VictimBounds) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write(BoundsHeader); err != nil {
		return err
	}
	for _, b := range victims {
		if err := w.Write(BoundsRecord(a, b)); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}
