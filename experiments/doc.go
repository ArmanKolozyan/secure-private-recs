// This package implements the experiments on the rating-leakage attack
// against Nudge's training. In the attack, one malicious server adds an
// integer Λ (the injection) to a chosen user's coordinate of an intermediate
// vector in the last power-iteration step, so that the first model row the
// servers reveal exposes which items that user rated.
//
// The package generates synthetic ratings matrices, computes the largest
// eigenvalue of their co-rating matrix, runs Nudge honestly to read the
// honest values that the injection has to exceed, derives the bounds on Λ from
// them, applies the attacker's rule to a revealed row, and writes bounds and
// run outcomes as CSV tables. The command-line drivers live in
// experiments/cmd.
package experiments
