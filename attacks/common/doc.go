// This package holds what the attack experiments share. It has four files.
//   - movielens.go loads MovieLens 100K as a 0/1 ratings matrix.
//   - nudge.go trains the model. Train runs Nudge's power iteration in one
//     process that plays all three servers, with whichever hooks of the share
//     package are attached. TrainWithServers runs Nudge's three servers, with
//     whichever hooks of the protocol package are attached.
//   - recs.go counts the ratings of the items, finds the items a user rated,
//     computes the recommendations Nudge serves from a model, and compares the
//     lists of two models.
//   - report.go prints in how many users' lists an item appears under a model,
//     and how close the model's rows are to those of an honest model.
package common
