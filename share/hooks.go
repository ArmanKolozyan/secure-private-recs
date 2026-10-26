package share

import . "github.com/NudgeArtifact/private-recs/uint128"

// LastIterationHook lets an experiment observe Nudge's power iteration. When it
// is not nil, PowerIteration calls it once, in the last iteration of the first
// component, with the three servers' shares of the vector that is about to be
// normalized into the first revealed model row.
var LastIterationHook func(v0, v1, v2 *Matrix[Share128])

// LastReshareHook lets an experiment make one server deviate from Nudge's
// protocol. When it is not nil, PowerIteration calls it once, in the last
// iteration of the first component, with the three servers' additive shares of
// the matrix-vector product U * v of the ratings matrix and the current vector,
// which has one entry per user, right before the servers reshare it. The hook
// may change the shares.
var LastReshareHook func(u0, u1, u2 *Matrix[Uint128])
