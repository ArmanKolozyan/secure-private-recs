package common

import (
	"os"
	"sync"

	"github.com/NudgeArtifact/private-recs/params"
	"github.com/NudgeArtifact/private-recs/protocol"
	"github.com/NudgeArtifact/private-recs/rand"
	"github.com/NudgeArtifact/private-recs/share"
)

// This function runs Nudge's power iteration on the ratings matrix 'U', in
// one process that plays all three servers, with whichever hooks of the share
// package are attached. It returns the model the servers reveal, one row per
// component, as signed fixed-point integers (a value x stands for
// x / 2^N_decimals).
func Train(U *share.Matrix[uint64], p *params.PowerItParams) [][]int64 {
	// splitting the matrix into secret shares for the three servers
	pool := rand.InitPRGPool(100)
	U0, U1, U2 := share.ShareMatrixRSS(U, pool)

	// running the power iteration, with the matrix scaled to fixed point as the
	// protocol prescribes (the last argument)
	B, _, _ := share.PowerIteration(U0, U1, U2, p, pool, true)
	return signedRows(B)
}

// This function trains the model on the ratings matrix 'U' with Nudge's three
// servers, which run in this process and talk to each other over local network
// connections, as in Nudge's own tests. Unlike Train, it runs the servers' own
// code, so the hooks of the protocol package apply. All three servers end up
// with the same model. The function returns server 1's copy, one row per
// component, as signed fixed-point integers.
func TrainWithServers(U *share.Matrix[uint64], p *params.PowerItParams) [][]int64 {
	// splitting the ratings matrix into shares for the three servers
	pool := share.InitPRGPoolFromMatrix(U)
	U0, U1, U2 := share.ShareMatrixRSS(U, pool)
	shares := []*share.Matrix[share.Share128]{U0, U1, U2}

	// silencing the servers while they run, since they print a line for nearly
	// every step
	null, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	stdout := os.Stdout
	os.Stdout = null
	defer func() {
		os.Stdout = stdout
		null.Close()
	}()

	// running the three servers and keeping server 1's model
	var B *share.Matrix[uint64]
	var wg sync.WaitGroup
	wg.Add(3)
	for id := 0; id < 3; id++ {
		go func(id int) {
			defer wg.Done()
			s := protocol.LaunchServerFromMatrix(id, "127.0.0.1", "127.0.0.1", "127.0.0.1", shares[id])
			s.PowerIteration(p, false, true)
			if id == 1 {
				B = s.Item_emb
			}
			s.Teardown()
		}(id)
	}
	wg.Wait()
	return signedRows(B)
}

// This function returns the rows of the model 'B' as signed numbers. Nudge
// stores a negative value in a uint64 in two's complement, so the conversion
// is a reinterpretation of the bits. For example, 18446744073709551615
// becomes -1.
func signedRows(B *share.Matrix[uint64]) [][]int64 {
	rows := make([][]int64, B.NRows())
	for c := range rows {
		rows[c] = make([]int64, B.NCols())
		for j := range rows[c] {
			rows[c][j] = int64(*B.Get(uint64(c), uint64(j)))
		}
	}
	return rows
}
