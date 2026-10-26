package share

// LastIterationHook lets an experiment observe Nudge's power iteration. When it
// is not nil, PowerIteration calls it once, in the last iteration of the first
// component, with the three servers' shares of the vector that is about to be
// normalized into the first revealed model row.
var LastIterationHook func(v0, v1, v2 *Matrix[Share128])
