package leakageattack

import (
	"math/rand"

	"github.com/NudgeArtifact/private-recs/share"
)

// Victim is the user the attack targets. When the synthetic matrix is
// generated, row 'Row' is given 'Rated' ratings on items drawn at random,
// so the experiment controls how many items the victim rated.
type Victim struct {
	Row   uint64
	Rated int
}

// SynthSpec describes a synthetic 0/1 ratings matrix: 'M' users, 'N' items,
// each entry 1 with probability 'Density', and then the rows of the 'Victims'
// overwritten as described in Victim. The generator is deterministic in 'Seed'.
type SynthSpec struct {
	M, N    uint64
	Density float64
	Seed    int64
	Victims []Victim
}

// Matrices maps a name to the synthetic matrix it stands for. 80x24 is a small
// matrix on which a protocol run takes a fraction of a second. User 3 is the
// victim and has 9 ratings.
var Matrices = map[string]SynthSpec{
	"80x24": {M: 80, N: 24, Density: 0.2, Seed: 42, Victims: []Victim{{Row: 3, Rated: 9}}},
}

// This function builds the matrix described by the given 'spec'.
func Synthetic(spec SynthSpec) *share.Matrix[uint64] {
	rng := rand.New(rand.NewSource(spec.Seed))
	U := share.MatrixZeros[uint64](spec.M, spec.N)
	one, zero := uint64(1), uint64(0)
	for i := uint64(0); i < spec.M; i++ {
		for j := uint64(0); j < spec.N; j++ {
			if rng.Float64() < spec.Density {
				U.Set(i, j, &one)
			}
		}
	}
	for _, v := range spec.Victims {
		for j := uint64(0); j < spec.N; j++ {
			U.Set(v.Row, j, &zero)
		}
		for _, j := range rng.Perm(int(spec.N))[:v.Rated] {
			U.Set(v.Row, uint64(j), &one)
		}
	}
	return U
}

// ItemsRatedBy returns the column indices of the items user 'i' rated.
func ItemsRatedBy(U *share.Matrix[uint64], i uint64) []uint64 {
	var items []uint64
	for j := uint64(0); j < U.NCols(); j++ {
		if *U.Get(i, j) != 0 {
			items = append(items, j)
		}
	}
	return items
}

// Ratings returns the total number of ratings in the matrix.
func Ratings(U *share.Matrix[uint64]) uint64 {
	var s uint64
	for _, x := range U.Data {
		if x != 0 {
			s++
		}
	}
	return s
}
