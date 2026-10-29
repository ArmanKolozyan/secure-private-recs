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

// Bounds computes, for the victim in row 'row' of the ratings matrix 'U', the
// honest values on and off the victim's items, taken from 'h' (see HonestRun),
// and the bounds on the injection.
func Bounds(U *share.Matrix[uint64], row uint64, h []float64, p *params.PowerItParams) VictimBounds {
	bounds := VictimBounds{Row: row, RatedItems: ItemsRatedBy(U, row), HOnMin: math.Inf(1)}
	rated := make([]bool, U.NCols())
	for _, j := range bounds.RatedItems {
		rated[j] = true
	}
	// taking the largest and smallest honest value on the victim's items, and the largest on the others
	for j, hj := range h {
		x := math.Abs(hj)
		if rated[j] {
			bounds.HOn = math.Max(bounds.HOn, x)
			bounds.HOnMin = math.Min(bounds.HOnMin, x)
		} else {
			bounds.HOff = math.Max(bounds.HOff, x)
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
	bounds.LowestCase1 = math.NaN()
	if allNonNegative {
		bounds.LowestCase1 = scale + log2(bounds.HOff-bounds.HOnMin)
	}
	bounds.LowestCase2 = scale + log2(bounds.HOn+bounds.HOff)
	bounds.LowestAttacker = scale + log2(2*float64(Ratings(U)))
	bounds.Highest = float64(p.Norm_decimals+2*p.N_decimals) - 0.5*math.Log2(float64(len(bounds.RatedItems)))
	return bounds
}

// AttackerExponent returns the exponent e of the attacker's choice Λ = 2^e: the
// middle, in bits, of the range from LowestAttacker to Highest, rounded to an
// integer. The attacker can compute it, since both ends depend only on the
// total number of ratings and on how many items the victim rated.
func (bounds VictimBounds) AttackerExponent() int {
	return int(math.Round((bounds.LowestAttacker + bounds.Highest) / 2))
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
func BoundsRecord(stats *MatrixStats, bounds VictimBounds) []string {
	f := func(x float64) string { return strconv.FormatFloat(x, 'f', 4, 64) }
	return []string{stats.Name, fmt.Sprint(stats.Users), fmt.Sprint(stats.Items), fmt.Sprint(stats.S),
		fmt.Sprint(bounds.Row), fmt.Sprint(len(bounds.RatedItems)),
		f(stats.Lambda1), f(stats.Q1Inf), f(bounds.HOn), f(bounds.HOff), f(bounds.HOnMin),
		f(bounds.LowestCase1), f(bounds.LowestCase2), f(bounds.LowestAttacker), f(bounds.Highest)}
}

// WriteBoundsCSV writes the table to a file for one matrix and its victims.
func WriteBoundsCSV(path string, stats *MatrixStats, victims []VictimBounds) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write(BoundsHeader); err != nil {
		return err
	}
	for _, bounds := range victims {
		if err := w.Write(BoundsRecord(stats, bounds)); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}
