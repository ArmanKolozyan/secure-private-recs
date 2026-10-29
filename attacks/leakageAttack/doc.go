// This package implements the experiments on the rating-leakage attack
// against Nudge's training. In the attack, one malicious server adds an
// integer Λ (the injection) to a chosen user's coordinate of an intermediate
// vector in the last power-iteration step, so that the first model row the
// servers reveal exposes which items that user rated.
//
// The files, from the inputs to the outcome:
//   - matrices.go: synthetic ratings matrices with a victim
//   - nudge.go: runs of Nudge's power iteration in one process that plays all
//     three servers, either honest, reading the honest values h, or with the
//     injection
//   - bounds.go: the bounds on Λ predicted from h, and the attacker's choice
//   - eigen.go: summary values of a matrix (MatrixStats), among them the
//     largest eigenvalue and eigenvector of the co-rating matrix.
//     The 'bounds' program prints them to check (1) that the honest values
//     are about the eigenvalue times the eigenvector's coordinates, and (2)
//     by how much the total number of ratings, which the attacker uses in place
//     of the eigenvalue, exceeds it
//   - guess.go: the attacker's guess for the victim's items from a revealed row
//   - verdict.go: the experiment's verdict on that guess
//   - results.go: the result of each attack run, as one CSV line
//
// The command-line programs live in attacks/leakageAttack/cmd.
package leakageattack
