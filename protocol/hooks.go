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
