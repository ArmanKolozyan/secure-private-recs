package protocol

import (
	. "github.com/NudgeArtifact/private-recs/share"
	. "github.com/NudgeArtifact/private-recs/uint128"
)

// This hook lets an experiment change what one server sends to a user when
// it serves recommendations. When it is not nil, every recommendation server
// calls it right before it sends a user its share of the user's scores, with
// the server's id (0, 1 or 2), the id of the user, and that share, one entry
// per item. The hook may change the share.
var ServingHook func(server int, user uint64, scores *Matrix[Uint128])

// This hook lets an experiment make server 0 change the model that the
// servers compute in training. The servers compute the model one row at a
// time and reveal each row once it is done. When the hook is not nil, server 0
// waits for server 1's shares of the row, computes the true row from them, and
// passes it to the hook. The hook returns the wanted row, which servers 1 and
// 2 should compute instead. In an honest reveal, server 0 sends the sum of its
// two shares of each entry to servers 1 and 2, and each of them adds to it the
// third share (which server 0 lacks). Here server 0 adds the wanted entry minus
// the true entry to that sum, so servers 1 and 2 compute the wanted entry.
var RevealHook func(truth []uint64) []uint64

// This hook lets an experiment make one server change a row of the model
// while the servers compute it. Normalize, which scales the row to length 1,
// ends with a Reshare, in which every server sends its additive share of the
// row, masked, to one other server. When the hook is not nil, every server
// calls it right before this Reshare, with the server's id (0, 1 or 2), the
// component and the step of the power iteration (both counted from 0), and
// the server's additive share of the row, one entry per item with N_decimals
// fractional bits. The hook may change the share. The receiver cannot check
// it, since a correct share looks random, and hence a change to the share changes
// the row by the same amount.
var NormalizeHook func(server, component, step int, row *Matrix[Uint128])

// This hook lets an experiment make server 0 change the result of the 0/1
// check, in which the servers test that every entry of the ratings matrix is
// 0 or 1. Each server holds a share of a sum that is 0 when every entry is 0
// or 1. Servers 1 and 2 send their shares to server 0, which adds the three
// shares and sends the sum back, and each server accepts the matrix when the
// sum is 0. When the hook is not nil, server 0 calls it with the sum right
// before it sends it, and the hook may change the sum. Servers 1 and 2 cannot
// check it, since they know only their own shares.
var CheckHook func(sum *Uint128)
