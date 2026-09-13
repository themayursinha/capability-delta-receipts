package capdelta

import (
	"bytes"
	"encoding/json"
	"testing"
)

func searchBudget(depth, branching, nodes int) SearchBudget {
	return SearchBudget{
		MaxDepth:     depth,
		MaxBranching: branching,
		MaxNodes:     nodes,
	}
}

func validSearchSpine() SearchTrajectory {
	return SearchTrajectory{
		SessionID:         "demo-001",
		Envelope:          demoEnvelope(),
		DeclaredAuthority: demoAuthority("attest tree-search exploration"),
		Budget:            searchBudget(4, 3, 8),
		Canary: Canary{
			Path:    "/host-canary/write.sh",
			Touched: false,
		},
	}
}

func receiptJSONField(t *testing.T, r Receipt, key string) (json.RawMessage, bool) {
	t.Helper()
	obj := receiptObject(t, r)
	raw, ok := obj[key]
	return raw, ok
}

// TestTreeSearchBudgetViolation proves CD-7: a SearchTrajectory whose
// explored node_count exceeds max_nodes, or whose branch depth exceeds
// max_depth, is rejected as malformed. No receipts are produced.
func TestTreeSearchBudgetViolation(t *testing.T) {
	t.Run("branch_depth_exceeds_max_depth", func(t *testing.T) {
		traj := validSearchSpine()
		traj.Budget = searchBudget(2, 3, 8)
		traj.Events = []Event{bugARuntimeEvent(1), bugBRuntimeEvent(2)}
		traj.Branches = []Branch{{
			BranchID:     "over-depth",
			ParentStepID: 2,
			ReasonPruned: "depth_ceiling",
			Events:       []Event{hostCanaryRequest(3)},
		}}

		got, err := EvaluateSearch(traj)
		if err == nil {
			t.Fatal("expected malformed rejection when branch depth exceeds max_depth")
		}
		if len(got.Receipts) != 0 {
			t.Fatalf("receipts on reject = %d, want 0", len(got.Receipts))
		}
	})

	t.Run("node_count_exceeds_max_nodes", func(t *testing.T) {
		traj := validSearchSpine()
		traj.Budget = searchBudget(8, 3, 2)
		traj.Events = []Event{bugARuntimeEvent(1), bugBRuntimeEvent(2)}
		traj.Branches = []Branch{{
			BranchID:     "extra-node",
			ParentStepID: 1,
			ReasonPruned: "low_value",
			Events:       []Event{hostCanaryRequest(3)},
		}}

		got, err := EvaluateSearch(traj)
		if err == nil {
			t.Fatal("expected malformed rejection when explored nodes exceed max_nodes")
		}
		if len(got.Receipts) != 0 {
			t.Fatalf("receipts on reject = %d, want 0", len(got.Receipts))
		}
	})
}

// TestTreeSearchPrunedBranchAttested proves CD-1/CD-2 on trees: a pruned
// branch's capability deltas appear in the receipt stream, but a
// boundary-crossing request on that branch never emits PAUSE.
func TestTreeSearchPrunedBranchAttested(t *testing.T) {
	traj := validSearchSpine()
	traj.Events = []Event{bugARuntimeEvent(1)}
	traj.Branches = []Branch{{
		BranchID:     "explore-egress",
		ParentStepID: 1,
		ReasonPruned: "value_below_threshold",
		Events:       []Event{egressRequest(2)},
	}}

	got, err := EvaluateSearch(traj)
	if err != nil {
		t.Fatalf("EvaluateSearch: %v", err)
	}

	var branch *Receipt
	var path *Receipt
	for i, r := range got.Receipts {
		raw, ok := receiptJSONField(t, r, "branch_id")
		if !ok {
			t.Fatalf("receipt[%d] missing branch_id (v2 tree receipt)", i)
		}
		switch string(raw) {
		case "null":
			if path == nil {
				cp := r
				path = &cp
			}
		case `"explore-egress"`:
			cp := r
			branch = &cp
		}
	}
	if path == nil {
		t.Fatal("executed-path receipt missing")
	}
	if branch == nil {
		t.Fatal("pruned branch deltas missing from receipts")
	}
	if path.Decision != DecisionAllow {
		t.Fatalf("executed path Decision = %q, want %q", path.Decision, DecisionAllow)
	}
	wantDelta := []string{CapNetEgress}
	if !sameStrings(branch.CapabilityDelta, wantDelta) {
		t.Fatalf("pruned branch CapabilityDelta = %v, want %v", branch.CapabilityDelta, wantDelta)
	}
	if branch.Decision == DecisionPause {
		t.Fatal("pruned branch emitted PAUSE; pruned branches are attested only")
	}
	if branch.Decision != DecisionAllow {
		t.Fatalf("pruned branch Decision = %q, want %q", branch.Decision, DecisionAllow)
	}
	if branch.RequiredProof != nil {
		t.Fatalf("pruned branch RequiredProof = %+v, want null", branch.RequiredProof)
	}
	if !hasSignal(branch.Signals, SignalRequestEgress, EvidenceBoundaryRequest) {
		t.Fatalf("pruned branch Signals = %+v, want kind %q", branch.Signals, SignalRequestEgress)
	}
}

// TestTreeSearchExecutedPathPauses proves CD-2 is preserved when branches
// are present: a boundary request on the executed path still PAUSEs, and
// the host canary stays untouched.
func TestTreeSearchExecutedPathPauses(t *testing.T) {
	traj := validSearchSpine()
	traj.Events = []Event{bugARuntimeEvent(1), hostCanaryRequest(2)}
	traj.Branches = []Branch{{
		BranchID:     "explore-b",
		ParentStepID: 1,
		ReasonPruned: "not_selected",
		Events:       []Event{bugBRuntimeEvent(2)},
	}}

	got, err := EvaluateSearch(traj)
	if err != nil {
		t.Fatalf("EvaluateSearch: %v", err)
	}

	var paused *Receipt
	var pruned *Receipt
	for i, r := range got.Receipts {
		raw, ok := receiptJSONField(t, r, "branch_id")
		if !ok {
			t.Fatalf("receipt[%d] missing branch_id (v2 tree receipt)", i)
		}
		switch {
		case string(raw) == "null" && r.StepID == 2:
			cp := r
			paused = &cp
		case string(raw) == `"explore-b"`:
			cp := r
			pruned = &cp
		}
	}
	if paused == nil {
		t.Fatal("executed-path boundary receipt missing")
	}
	if paused.Decision != DecisionPause {
		t.Fatalf("executed path Decision = %q, want %q", paused.Decision, DecisionPause)
	}
	if paused.EnvelopeAfter.State != EnvelopeBoundaryCrossing {
		t.Fatalf("executed path EnvelopeAfter = %q, want %q", paused.EnvelopeAfter.State, EnvelopeBoundaryCrossing)
	}
	if paused.RequiredProof == nil {
		t.Fatal("executed path RequiredProof = nil, want fresh_authorization on PAUSE")
	}
	if !sameStrings(paused.CapabilityDelta, []string{CapHostExec}) {
		t.Fatalf("executed path CapabilityDelta = %v, want [host_exec]", paused.CapabilityDelta)
	}
	if got.Canary.Touched {
		t.Fatal("canary was touched; guarded path must emit PAUSE before execution")
	}
	if traj.Canary.Touched {
		t.Fatal("input Canary.Touched mutated")
	}
	if pruned == nil {
		t.Fatal("pruned in-envelope branch missing from receipts")
	}
	if pruned.Decision == DecisionPause {
		t.Fatal("pruned in-envelope branch paused")
	}
	if !sameStrings(pruned.CapabilityDelta, []string{CapHeapEscape, CapNativeExec}) {
		t.Fatalf("pruned branch CapabilityDelta = %v, want [heap_escape native_exec]", pruned.CapabilityDelta)
	}
}

// TestTreeSearchCanonical proves CD-6 on trees: identical tree input with
// branches in different orders yields byte-identical encoded receipts.
func TestTreeSearchCanonical(t *testing.T) {
	alpha := Branch{
		BranchID:     "alpha",
		ParentStepID: 1,
		ReasonPruned: "low_value",
		Events:       []Event{bugBRuntimeEvent(2)},
	}
	beta := Branch{
		BranchID:     "beta",
		ParentStepID: 1,
		ReasonPruned: "low_value",
		Events:       []Event{egressRequest(3)},
	}

	eval := func(branches []Branch) Evaluation {
		t.Helper()
		traj := validSearchSpine()
		traj.Events = []Event{bugARuntimeEvent(1)}
		traj.Branches = branches
		got, err := EvaluateSearch(traj)
		if err != nil {
			t.Fatalf("EvaluateSearch: %v", err)
		}
		return got
	}

	first := eval([]Branch{alpha, beta})
	second := eval([]Branch{beta, alpha})
	if len(first.Receipts) != len(second.Receipts) {
		t.Fatalf("len(Receipts) = %d, %d, want equal", len(first.Receipts), len(second.Receipts))
	}
	if len(first.Receipts) != 3 {
		t.Fatalf("len(Receipts) = %d, want 3 (path + 2 branches)", len(first.Receipts))
	}
	for i := range first.Receipts {
		a := first.Receipts[i].Encode()
		b := second.Receipts[i].Encode()
		if !bytes.Equal(a, b) {
			t.Fatalf("branch order changed encoded receipt[%d]\nA: %sB: %s", i, a, b)
		}
		if recomputedHash(first.Receipts[i]) != first.Receipts[i].Hash {
			t.Fatalf("receipt[%d] stored hash does not match canonical payload", i)
		}
		if i == 0 {
			continue
		}
		if first.Receipts[i].PrevHash != first.Receipts[i-1].Hash {
			t.Fatalf("receipt[%d].prev_hash = %q, want %q", i, first.Receipts[i].PrevHash, first.Receipts[i-1].Hash)
		}
	}

	for i, r := range first.Receipts {
		if r.ReceiptVersion != 2 {
			t.Fatalf("receipt[%d] receipt_version = %d, want 2 for tree input", i, r.ReceiptVersion)
		}
		raw, ok := receiptJSONField(t, r, "node_count")
		if !ok {
			t.Fatalf("receipt[%d] missing node_count", i)
		}
		var n int
		if err := json.Unmarshal(raw, &n); err != nil {
			t.Fatalf("receipt[%d] node_count: %v", i, err)
		}
		if n != i+1 {
			t.Fatalf("receipt[%d] node_count = %d, want %d", i, n, i+1)
		}
		budgetRaw, ok := receiptJSONField(t, r, "search_budget")
		if !ok {
			t.Fatalf("receipt[%d] missing search_budget", i)
		}
		var budget SearchBudget
		if err := json.Unmarshal(budgetRaw, &budget); err != nil {
			t.Fatalf("receipt[%d] search_budget: %v", i, err)
		}
		want := searchBudget(4, 3, 8)
		if budget != want {
			t.Fatalf("receipt[%d] search_budget = %+v, want %+v", i, budget, want)
		}
	}
}
