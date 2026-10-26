package leakageattack

import (
	"math"

	"github.com/NudgeArtifact/private-recs/share"
)

// coRating returns the co-rating matrix M = UᵀU of 'U': entry (a, b) counts
// the users who rated both items a and b.
func coRating(U *share.Matrix[uint64]) []float64 {
	n := int(U.NCols())
	M := make([]float64, n*n)
	for i := uint64(0); i < U.NRows(); i++ {
		items := ItemsRatedBy(U, i)
		for _, a := range items {
			for _, b := range items {
				M[int(a)*n+int(b)]++
			}
		}
	}
	return M
}

// topEigen returns the largest eigenvalue of the symmetric matrix 'M' and its
// eigenvector of length 1 via power iteration, run until the eigenvalue
// estimate no longer changes.
func topEigen(M []float64, n int) (float64, []float64) {
	v := make([]float64, n)
	// starting from the all-ones vector
	for j := range v {
		v[j] = 1
	}
	v = unit(v)
	lambda := 0.0
	for it := 0; it < 100000; it++ {
		// multiplying by M, which makes the dominant direction grow fastest
		w := matVec(M, n, v)
		// estimating the eigenvalue, then rescaling to length 1
		l := dot(v, w)
		v = unit(w)
		// stopping when the estimate no longer changes
		if math.Abs(l-lambda) <= 1e-13*math.Max(l, 1) {
			lambda = l
			break
		}
		lambda = l
	}
	return lambda, v
}

// matVec returns the product of the n×n matrix 'M' with the vector 'x'.
func matVec(M []float64, n int, x []float64) []float64 {
	y := make([]float64, n)
	for a := 0; a < n; a++ {
		row := M[a*n : (a+1)*n]
		s := 0.0
		for b, m := range row {
			s += m * x[b]
		}
		y[a] = s
	}
	return y
}

// dot returns the inner product of 'a' and 'b'.
func dot(a, b []float64) float64 {
	s := 0.0
	for j := range a {
		s += a[j] * b[j]
	}
	return s
}

// unit returns 'a' scaled to length 1.
func unit(a []float64) []float64 {
	norm := math.Sqrt(dot(a, a))
	u := make([]float64, len(a))
	for j := range a {
		u[j] = a[j] / norm
	}
	return u
}
