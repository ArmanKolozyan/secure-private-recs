package leakageattack

import (
	"math"

	"github.com/NudgeArtifact/private-recs/params"
	"github.com/NudgeArtifact/private-recs/rand"
	"github.com/NudgeArtifact/private-recs/share"
	"github.com/NudgeArtifact/private-recs/uint128"
)

// HonestRun runs Nudge's power iteration honestly on the ratings matrix 'U', in
// one process that plays all three servers. Only the first component is
// computed, since the attack concerns only the first revealed row. It returns
// h, the vector that entered normalization in the last iteration, in real
// units. Nudge does not reveal h, so it is read with the share.HonestValuesHook
// hook.
func HonestRun(U *share.Matrix[uint64], p *params.PowerItParams) []float64 {
	// attaching the hook that reads h, and detaching it when the run is over
	var h []float64
	share.HonestValuesHook = func(h0, h1, h2 *share.Matrix[share.Share128]) {
		// putting h back together from the three servers' shares, with a separate
		// performance log so that this does not count as communication of the run
		z := share.MatrixRecoverFromRSS(h0, h1, h2, new(share.PerfLog))
		h = make([]float64, z.NRows())
		for j := range h {
			// converting from Nudge's fixed point (signed integers times
			// 2^N_decimals) to real units
			h[j] = float64(int64(*z.Get(uint64(j), 0))) / math.Ldexp(1, p.N_decimals)
		}
	}
	defer func() { share.HonestValuesHook = nil }()

	// running Nudge, during which the hook fills 'h'
	runNudge(U, p)
	return h
}

// AttackRun runs Nudge's power iteration on the ratings matrix 'U' in one
// process that plays all three servers, one of which is malicious. In the last
// iteration of the first component, that server adds Λ = 2^'exponent' to its
// share of the matrix-vector product U * v of the ratings matrix and the
// current vector, at the entry of the victim 'victim' (the product has one
// entry per user), right before the reshare (see share.AttackHook).
// A negative 'exponent' means no injection, which is an honest run.
// Only the first component is computed. It returns the first revealed row as
// signed fixed-point integers, and the sign of the honest values in the last
// iteration, read on the items the victim did not rate, whose values the
// injection does not change: "positive" when they are all at least 0,
// "negative" when they are all at most 0, and "mixed" otherwise.
func AttackRun(U *share.Matrix[uint64], p *params.PowerItParams, victim uint64, exponent int) ([]int64, string) {
	// injecting only when an exponent is given, a negative one means an honest run
	if exponent >= 0 {
		// building Λ = 2^exponent as a 128-bit integer: the number 1 (high half
		// 0, low half 1), shifted left by 'exponent' bits
		lambda := uint128.MakeUint128(0, 1)
		lambda.LshInPlace(uint(exponent))

		// attaching the hook, which Nudge calls with the three servers' additive
		// shares of the product U * v (one entry per user), right before the
		// servers reshare it in the last iteration of the first component
		share.AttackHook = func(u0, u1, u2 *share.Matrix[uint128.Uint128]) {
			// Adding Λ, modulo 2^128, to the victim's entry of server 1's share.
			// Any server's share would do, since the reshare is linear in each
			// of them.
			u1.Data[victim].AddInPlace(lambda)
		}

		// detaching the hook when the run is over, so that later runs are honest
		defer func() { share.AttackHook = nil }()
	}

	// reading, in the last iteration, the signs of the honest values on the
	// items the victim did not rate, whose values the injection leaves unchanged
	rated := make([]bool, U.NCols())
	for _, j := range ItemsRatedBy(U, victim) {
		rated[j] = true
	}
	sign := ""
	share.HonestValuesHook = func(h0, h1, h2 *share.Matrix[share.Share128]) {
		positive, negative := false, false
		for j := uint64(0); j < h0.NRows(); j++ {
			if rated[j] {
				continue
			}
			// Putting the value back together from the servers' shares, in 128
			// bits.
			x := uint128.Add(&h0.Data[j].First, &h0.Data[j].Second)
			x.AddInPlace(&h1.Data[j].First)
			switch {
			case uint128.IsZero(x):
			case uint128.CheckPositiveUint64(x):
				positive = true
			default:
				negative = true
			}
		}
		switch {
		case positive && negative:
			sign = "mixed"
		case negative:
			sign = "negative"
		default:
			sign = "positive"
		}
	}
	defer func() { share.HonestValuesHook = nil }()

	// running Nudge and returning the first row the servers reveal, with the sign
	return runNudge(U, p), sign
}

// runNudge splits the ratings matrix 'U' into secret shares for the three
// servers and runs Nudge's power iteration on them, in one process that plays
// all three servers, with whichever hooks are attached. Only the first
// component is computed. It returns the first revealed row as signed
// fixed-point integers.
func runNudge(U *share.Matrix[uint64], p *params.PowerItParams) []int64 {
	// computing only the first component, without changing the caller's parameters
	q := *p
	q.K = 1

	// splitting the matrix into secret shares for the three servers
	pool := rand.InitPRGPool(100)
	U0, U1, U2 := share.ShareMatrixRSS(U, pool)

	// running the power iteration, with the matrix scaled to fixed point as the
	// protocol prescribes (the last argument)
	B, _, _ := share.PowerIteration(U0, U1, U2, &q, pool, true)
	return rowAsSigned(B, 0)
}

// rowAsSigned returns row 'i' of a matrix revealed by Nudge as signed numbers.
// Nudge stores a negative value in a uint64 in two's complement, so the
// conversion is a reinterpretation of the bits.
// Example: row [5, 18446744073709551615] becomes [5, -1].
func rowAsSigned(B *share.Matrix[uint64], i uint64) []int64 {
	row := make([]int64, B.NCols())
	for j := range row {
		row[j] = int64(*B.Get(i, uint64(j)))
	}
	return row
}
