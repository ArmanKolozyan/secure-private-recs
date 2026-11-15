// This file prints how an attacked model differs from an honest one, in how
// many lists it puts an item and in how close its rows are to those of an
// honest model.

package common

import (
	"fmt"
	"math"
	"slices"

	"github.com/NudgeArtifact/private-recs/share"
)

// This function counts the users whose list of 'n' items holds the item
// 'target' under the model 'B', and returns the count. It also prints one line
// with 'name', the count, and how close the rows are to length 1 and to being
// orthogonal to each other (see the function 'describeRows'). The entries of
// 'B' have 'decimals' fractional bits.
func Report(name string, U *share.Matrix[uint64], B [][]int64, target uint64, n, decimals int) int {
	// counting the users whose list holds the target item
	count := 0
	for _, list := range Recommendations(U, B, n) {
		if slices.Contains(list, target) {
			count++
		}
	}
	fmt.Printf("%s: target item in %d of %d lists, %s\n", name, count, U.NRows(), describeRows(B, decimals))
	return count
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
