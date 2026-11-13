package common

import (
	"github.com/NudgeArtifact/private-recs/params"
	"github.com/NudgeArtifact/private-recs/rand"
	"github.com/NudgeArtifact/private-recs/share"
)

// This function runs Nudge's power iteration on the ratings matrix 'U', in
// one process that plays all three servers, with whichever hooks are
// attached. It returns the model the servers reveal, one row per component,
// as signed fixed-point integers (a value x stands for x / 2^N_decimals).
func Train(U *share.Matrix[uint64], p *params.PowerItParams) [][]int64 {
	// splitting the matrix into secret shares for the three servers
	pool := rand.InitPRGPool(100)
	U0, U1, U2 := share.ShareMatrixRSS(U, pool)

	// running the power iteration, with the matrix scaled to fixed point as the
	// protocol prescribes (the last argument)
	B, _, _ := share.PowerIteration(U0, U1, U2, p, pool, true)

	// Converting every revealed row to signed numbers. Nudge stores a negative
	// value in a uint64 in two's complement, so the conversion is a
	// reinterpretation of the bits. For example, 18446744073709551615 becomes
	// -1.
	rows := make([][]int64, B.NRows())
	for c := range rows {
		rows[c] = make([]int64, B.NCols())
		for j := range rows[c] {
			rows[c][j] = int64(*B.Get(uint64(c), uint64(j)))
		}
	}
	return rows
}
