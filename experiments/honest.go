package experiments

import (
	"math"

	"github.com/NudgeArtifact/private-recs/params"
	"github.com/NudgeArtifact/private-recs/rand"
	"github.com/NudgeArtifact/private-recs/share"
)

// HonestRun runs Nudge's power iteration honestly on the ratings matrix 'U', in
// one process that plays all three servers. Only the first component is
// computed, since the attack concerns only the first revealed row. It returns
// h, the vector that entered normalization in the last iteration, in real
// units. Nudge does not reveal h, so it is read with the share.LastIterationHook
// hook.
func HonestRun(U *share.Matrix[uint64], p *params.PowerItParams) []float64 {
	// computing only the first component, without changing the caller's parameters
	q := *p
	q.K = 1

	// attaching the hook that reads h, and detaching it when the run is over
	var h []float64
	share.LastIterationHook = func(v0, v1, v2 *share.Matrix[share.Share128]) {
		// putting h back together from the three servers' shares, with a separate
		// performance log so that this does not count as communication of the run
		z := share.MatrixRecoverFromRSS(v0, v1, v2, new(share.PerfLog))
		h = make([]float64, z.NRows())
		for j := range h {
			// converting from Nudge's fixed point (signed integers times
			// 2^N_decimals) to real units
			h[j] = float64(int64(*z.Get(uint64(j), 0))) / math.Ldexp(1, q.N_decimals)
		}
	}
	defer func() { share.LastIterationHook = nil }()

	// splitting the matrix into secret shares for the three servers
	pool := rand.InitPRGPool(100)
	U0, U1, U2 := share.ShareMatrixRSS(U, pool)

	// running the power iteration, with the matrix scaled to fixed point as the
	// protocol prescribes (the last argument), during which the hook fills 'h'
	share.PowerIteration(U0, U1, U2, &q, pool, true)
	return h
}
