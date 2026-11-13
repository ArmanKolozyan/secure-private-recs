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
