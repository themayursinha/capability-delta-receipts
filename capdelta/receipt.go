package capdelta

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

const hashPrefix = "sha256:"

// genesisPrevHash is the predecessor of the first receipt: SHA-256 of
// the empty payload. Every line carries a non-empty prev_hash (CD-6).
const genesisPrevHash = hashPrefix + "e3b0c44298fc1c149afbf4c8996fb92427ae41e490166ae4ba7b5b37bcd8deac"

// Encode returns one compact JSONL line for r.
//
// Hashing mirrors the mcp-visor audit logger (CD-6): PrevHash is taken
// from the previous receipt's final Hash (genesisPrevHash on the first
// line) and must already be set; only Hash is cleared; the canonical
// JSON of the cleared receipt is SHA-256'd; Hash is then set to
// "sha256:" + lowercase hex. The returned bytes are the sealed object
// plus a trailing newline.
func (r *Receipt) Encode() []byte {
	r.Hash = ""
	payload, err := json.Marshal(r)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(payload)
	r.Hash = hashPrefix + hex.EncodeToString(sum[:])
	out, err := json.Marshal(r)
	if err != nil {
		return nil
	}
	return append(out, '\n')
}

func cloneCaps(in []string) []string {
	out := make([]string, 0, len(in))
	return append(out, in...)
}

func newlyHeld(add, held []string) []string {
	have := capSet(held)
	out := make([]string, 0, len(add))
	for _, c := range add {
		if have[c] {
			continue
		}
		out = append(out, c)
	}
	return out
}

func unionLattice(before, delta []string) []string {
	have := capSet(before)
	for _, c := range delta {
		have[c] = true
	}
	out := make([]string, 0, len(have))
	for _, c := range lattice {
		if have[c] {
			out = append(out, c)
		}
	}
	return out
}

func highestCapability(caps []string) string {
	rank := make(map[string]int, len(lattice))
	for i, c := range lattice {
		rank[c] = i
	}
	best := ""
	bestRank := -1
	for _, c := range caps {
		if r, ok := rank[c]; ok && r > bestRank {
			bestRank = r
			best = c
		}
	}
	return best
}

func capSet(caps []string) map[string]bool {
	out := make(map[string]bool, len(caps))
	for _, c := range caps {
		out[c] = true
	}
	return out
}
