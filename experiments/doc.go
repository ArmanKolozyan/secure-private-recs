// This package implements the experiments on the rating-leakage attack
// against Nudge's training. In the attack, one malicious server adds an
// integer Λ (the injection) to a chosen user's coordinate of an intermediate
// vector in the last power-iteration step, so that the first model row the
// servers reveal exposes which items that user rated.
//
// The package generates synthetic ratings matrices, computes the exact values
// of the honest computation on a matrix and the bounds on Λ that follow from
// them, and writes those as CSV tables. The command-line drivers live in
// experiments/cmd.
package experiments
