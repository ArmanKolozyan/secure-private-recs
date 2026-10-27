package share

import . "github.com/NudgeArtifact/private-recs/uint128"

// HonestValuesHook lets an experiment read the honest values h, which Nudge
// never reveals. When it is not nil, PowerIteration calls it once, in the last
// iteration of the first component, with the three servers' shares of the
// vector that is about to be normalized into the first revealed model row. In
// an honest run, that vector is h.
var HonestValuesHook func(h0, h1, h2 *Matrix[Share128])

// AttackHook lets an experiment make one server deviate from Nudge's
// protocol. When it is not nil, PowerIteration calls it once, in the last
// iteration of the first component, with the three servers' additive shares of
// the matrix-vector product U * v of the ratings matrix and the current vector,
// which has one entry per user, right before the servers reshare it. The hook
// may change the shares.
var AttackHook func(u0, u1, u2 *Matrix[Uint128])
