package capdelta

import "testing"

func hostCanaryRequest(step int) Event {
	return Event{
		Type:         EventRequest,
		StepID:       step,
		Target:       "host",
		Effect:       EffectHostExec,
		EffectTarget: "/host-canary/write.sh",
		Path:         "/host-canary/write.sh",
		Observation:  "requested exec of /host-canary/write.sh",
		Digest:       sourceDigest("request-host-canary"),
	}
}

// TestCompositionPaused proves D3/CD-2: composing in-scope bug A and bug B
// into a host-canary effect is outside the envelope, so the guarded path
// emits PAUSE_REQUIRE_NEW_PROOF with HIGH -> BOUNDARY_CROSSING before any
// effect, and the canary stays untouched. Executing first is attack class
// effect-before-pause; skipping the pause is boundary-composition-bypass.
func TestCompositionPaused(t *testing.T) {
	traj := Trajectory{
		SessionID:         "demo-001",
		Envelope:          demoEnvelope(),
		DeclaredAuthority: demoAuthority("compose bug A + bug B toward host canary"),
		Canary: Canary{
			Path:    "/host-canary/write.sh",
			Touched: false,
		},
		Events: []Event{
			bugARuntimeEvent(1),
			bugBRuntimeEvent(2),
			hostCanaryRequest(3),
		},
	}

	got := Evaluate(traj)
	if len(got.Receipts) != 3 {
		t.Fatalf("len(Receipts) = %d, want 3", len(got.Receipts))
	}
	if got.Receipts[0].Decision != DecisionAllow || got.Receipts[1].Decision != DecisionAllow {
		t.Fatalf("in-scope prefix decisions = %q, %q, want ALLOW, ALLOW", got.Receipts[0].Decision, got.Receipts[1].Decision)
	}

	r := got.Receipts[2]
	if r.StepID != 3 {
		t.Fatalf("step_id = %d, want 3", r.StepID)
	}
	if r.Decision != DecisionPause {
		t.Fatalf("Decision = %q, want %q", r.Decision, DecisionPause)
	}
	if r.EnvelopeTransition != "HIGH -> BOUNDARY_CROSSING" {
		t.Fatalf("EnvelopeTransition = %q, want %q", r.EnvelopeTransition, "HIGH -> BOUNDARY_CROSSING")
	}
	if r.EnvelopeBefore.State != EnvelopeHigh || r.EnvelopeAfter.State != EnvelopeBoundaryCrossing {
		t.Fatalf("envelope states before=%q after=%q, want HIGH -> BOUNDARY_CROSSING", r.EnvelopeBefore.State, r.EnvelopeAfter.State)
	}
	wantBefore := []string{CapOOBRead, CapOOBWrite, CapHeapEscape, CapNativeExec}
	if !sameStrings(r.CapabilityBefore, wantBefore) {
		t.Fatalf("CapabilityBefore = %v, want %v", r.CapabilityBefore, wantBefore)
	}
	wantDelta := []string{CapHostExec}
	if !sameStrings(r.CapabilityDelta, wantDelta) {
		t.Fatalf("CapabilityDelta = %v, want %v", r.CapabilityDelta, wantDelta)
	}
	if r.ObservedCapability != CapHostExec {
		t.Fatalf("ObservedCapability = %q, want %q", r.ObservedCapability, CapHostExec)
	}
	if r.NominalPermissionsChanged {
		t.Fatal("NominalPermissionsChanged = true, want false")
	}
	if !r.EffectiveAuthorityChanged {
		t.Fatal("EffectiveAuthorityChanged = false, want true")
	}
	if r.Reason != ReasonEffectOutsideEnvelope {
		t.Fatalf("Reason = %q, want %q", r.Reason, ReasonEffectOutsideEnvelope)
	}
	if r.RequiredProof == nil {
		t.Fatal("RequiredProof = nil, want fresh_authorization on PAUSE")
	}
	if r.RequiredProof.Type != "fresh_authorization" {
		t.Fatalf("RequiredProof.Type = %q, want %q", r.RequiredProof.Type, "fresh_authorization")
	}
	if !hasSignal(r.Signals, SignalHostExec, EvidenceBoundaryRequest) {
		t.Fatalf("Signals = %+v, want kind %q at evidence_level %q", r.Signals, SignalHostExec, EvidenceBoundaryRequest)
	}
	if got.Canary.Touched {
		t.Fatal("canary was touched; guarded path must emit PAUSE before execution")
	}
	if traj.Canary.Touched {
		t.Fatal("input canary was mutated; Evaluate must not execute the boundary effect")
	}
}
