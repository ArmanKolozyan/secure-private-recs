// This package holds what the attack experiments share. It has three files.
//   - movielens.go loads MovieLens 100K as a 0/1 ratings matrix.
//   - nudge.go has Train, which runs Nudge's power iteration in one process
//     that plays all three servers, with whichever hooks are attached.
//   - recs.go finds the items a user rated, computes the recommendations Nudge
//     serves from a model, and compares the lists of two models.
package common
