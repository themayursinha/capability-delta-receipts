package capdelta

import (
	"fmt"
	"sort"
)

// EvaluateSearch reduces a tree-search trajectory into one receipt per
// explored event (executed path, then pruned branches in branch_id
// order). Every event is reduced by the existing detector. Pruned
// branches never PAUSE. A CD-7 ceiling violation is malformed input:
// no receipts are returned.
func EvaluateSearch(traj SearchTrajectory) (Evaluation, error) {
	if err := checkSearchBudget(traj); err != nil {
		return Evaluation{}, err
	}

	base := Trajectory{
		SessionID:         traj.SessionID,
		Envelope:          traj.Envelope,
		DeclaredAuthority: traj.DeclaredAuthority,
		Canary:            traj.Canary,
		EphemeralCanary:   traj.EphemeralCanary,
		Events:            traj.Events,
	}
	eval := Evaluation{
		Receipts:        make([]Receipt, 0, exploredNodes(traj)),
		Canary:          Canary{Path: traj.Canary.Path, Touched: false},
		EphemeralCanary: Canary{Path: traj.EphemeralCanary.Path, Touched: false},
	}

	held := []string{CapReadSandboxMem}
	envelopeState := EnvelopeHigh
	prevHash := genesisPrevHash
	nodeCount := 0
	budget := traj.Budget
	heldAfter := make(map[int][]string, len(traj.Events))

	stamp := func(r *Receipt, branchID *jsonNullString) {
		nodeCount++
		r.ReceiptVersion = receiptVersionTree
		r.BranchID = branchID
		r.NodeCount = nodeCount
		r.SearchBudget = &budget
		r.PrevHash = prevHash
		_ = r.Encode()
		prevHash = r.Hash
	}

	for _, ev := range traj.Events {
		r := evaluateEvent(base, ev, held, envelopeState, false)
		stamp(&r, executedPathBranchID())
		eval.Receipts = append(eval.Receipts, r)
		held = r.CapabilityAfter
		envelopeState = r.EnvelopeAfter.State
		heldAfter[ev.StepID] = cloneCaps(held)
	}

	branches := append([]Branch(nil), traj.Branches...)
	sort.Slice(branches, func(i, j int) bool {
		return branches[i].BranchID < branches[j].BranchID
	})
	for _, br := range branches {
		branchHeld := cloneCaps(heldAfter[br.ParentStepID])
		branchEnvelope := EnvelopeHigh
		id := prunedBranchID(br.BranchID)
		for _, ev := range br.Events {
			r := evaluateEvent(base, ev, branchHeld, branchEnvelope, true)
			stamp(&r, id)
			eval.Receipts = append(eval.Receipts, r)
			branchHeld = r.CapabilityAfter
			branchEnvelope = r.EnvelopeAfter.State
		}
	}
	return eval, nil
}

func exploredNodes(traj SearchTrajectory) int {
	n := len(traj.Events)
	for _, br := range traj.Branches {
		n += len(br.Events)
	}
	return n
}

// checkSearchBudget enforces CD-7: cumulative explored nodes, depth, and
// branching never exceed the declared ceilings. Fail closed.
func checkSearchBudget(traj SearchTrajectory) error {
	if traj.Budget.MaxDepth < 0 || traj.Budget.MaxBranching < 0 || traj.Budget.MaxNodes < 0 {
		return fmt.Errorf("malformed search trajectory: negative search budget")
	}
	if len(traj.Events) == 0 {
		return fmt.Errorf("malformed search trajectory: events must contain at least one event")
	}

	depths := make(map[int]int, len(traj.Events))
	seenStep := make(map[int]bool, len(traj.Events))
	for i, ev := range traj.Events {
		if seenStep[ev.StepID] {
			return fmt.Errorf("malformed search trajectory: duplicate step_id %d", ev.StepID)
		}
		seenStep[ev.StepID] = true
		d := i + 1
		depths[ev.StepID] = d
		if d > traj.Budget.MaxDepth {
			return fmt.Errorf("malformed search trajectory: depth exceeds max_depth")
		}
	}

	children := make(map[int]int, len(traj.Events))
	for i := range traj.Events {
		if i+1 < len(traj.Events) {
			children[traj.Events[i].StepID]++
		}
	}

	nodes := len(traj.Events)
	seenBranch := make(map[string]bool, len(traj.Branches))
	for _, br := range traj.Branches {
		if br.BranchID == "" {
			return fmt.Errorf("malformed search trajectory: missing branch_id")
		}
		if seenBranch[br.BranchID] {
			return fmt.Errorf("malformed search trajectory: duplicate branch_id %q", br.BranchID)
		}
		seenBranch[br.BranchID] = true
		parentDepth, ok := depths[br.ParentStepID]
		if !ok {
			return fmt.Errorf("malformed search trajectory: unknown parent_step_id %d", br.ParentStepID)
		}
		if len(br.Events) == 0 {
			return fmt.Errorf("malformed search trajectory: branch %q has no events", br.BranchID)
		}
		children[br.ParentStepID]++
		for j := range br.Events {
			if parentDepth+j+1 > traj.Budget.MaxDepth {
				return fmt.Errorf("malformed search trajectory: depth exceeds max_depth")
			}
		}
		nodes += len(br.Events)
	}

	if nodes > traj.Budget.MaxNodes {
		return fmt.Errorf("malformed search trajectory: node_count exceeds max_nodes")
	}
	for step, n := range children {
		if n > traj.Budget.MaxBranching {
			return fmt.Errorf("malformed search trajectory: branching exceeds max_branching at step_id %d", step)
		}
	}
	return nil
}
