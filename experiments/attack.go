package experiments

import (
	"github.com/NudgeArtifact/private-recs/params"
	"github.com/NudgeArtifact/private-recs/rand"
	"github.com/NudgeArtifact/private-recs/share"
	"github.com/NudgeArtifact/private-recs/uint128"
)

// AttackRun runs Nudge's power iteration on the ratings matrix 'U' in one
// process that plays all three servers, one of which is malicious. In the last
// iteration of the first component, that server adds Λ = 2^'exponent' to its
// share of the matrix-vector product U * v of the ratings matrix and the
// current vector, at the entry of the victim 'victim' (the product has one
// entry per user), right before the reshare (see share.LastReshareHook). 
// A negative 'exponent' means no injection, which is an honest run. 
// Only the first component is computed. It returns the first revealed row as 
// signed fixed-point integers.
func AttackRun(U *share.Matrix[uint64], p *params.PowerItParams, victim uint64, exponent int) []int64 {
	// computing only the first component, without changing the caller's parameters
	q := *p
	q.K = 1

	// injecting only when an exponent is given, a negative one means an honest run
	if exponent >= 0 {
		// building Λ = 2^exponent as a 128-bit integer: the number 1 (high half
		// 0, low half 1), shifted left by 'exponent' bits
		lambda := uint128.MakeUint128(0, 1)
		lambda.LshInPlace(uint(exponent))

		// attaching the hook, which Nudge calls with the three servers' additive
		// shares of the product U * v (one entry per user), right before the
		// servers reshare it in the last iteration of the first component
		share.LastReshareHook = func(u0, u1, u2 *share.Matrix[uint128.Uint128]) {
			// Adding Λ, modulo 2^128, to the victim's entry of server 1's share.
			// Any server's share would do, since the reshare is linear in each
			// of them.
			u1.Data[victim].AddInPlace(lambda)
		}

		// detaching the hook when the run is over, so that later runs are honest
		defer func() { share.LastReshareHook = nil }()
	}

	// splitting the matrix into secret shares for the three servers
	pool := rand.InitPRGPool(100)
	U0, U1, U2 := share.ShareMatrixRSS(U, pool)

	// running the power iteration, with the matrix scaled to fixed point as the
	// protocol prescribes (the last argument)
	B, _, _ := share.PowerIteration(U0, U1, U2, &q, pool, true)
	return RowAsSigned(B, 0)
}
