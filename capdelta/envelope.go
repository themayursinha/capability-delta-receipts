package capdelta

// effectInEnvelope is the D2/D3 boundary predicate.
//
//	effect_target ∈ envelope  →  ALLOW
//	effect_target ∉ envelope  →  PAUSE_REQUIRE_NEW_PROOF
//
// Only this predicate decides PAUSE. Heuristics supply evidence for
// deltas; they never flip the decision. Host exec, network egress, and
// canary access are always outside the envelope. Any other event is
// inside iff EffectTarget is empty or equals DeclaredTarget (CD-1/CD-2).
func effectInEnvelope(env Envelope, ev Event) bool {
	switch ev.Effect {
	case EffectHostExec, EffectNetEgress, EffectCanaryAccess:
		return false
	}
	if ev.EffectTarget == "" {
		return true
	}
	return ev.EffectTarget == env.DeclaredTarget
}

// boundaryResult is the authorization outcome of one step.
type boundaryResult struct {
	Decision      string
	After         string
	Reason        string
	RequiredProof *RequiredProof
}

// applyBoundaryPredicate evaluates D2/D3 for one event. In-envelope
// accumulation always ALLOW (CD-1). A crossing emits PAUSE and names
// the fresh proof; the caller must not execute the effect (CD-2).
func applyBoundaryPredicate(env Envelope, ev Event, envelopeBefore string) boundaryResult {
	if effectInEnvelope(env, ev) {
		return boundaryResult{
			Decision: DecisionAllow,
			After:    envelopeBefore,
		}
	}
	return boundaryResult{
		Decision:      DecisionPause,
		After:         EnvelopeBoundaryCrossing,
		Reason:        ReasonEffectOutsideEnvelope,
		RequiredProof: pauseProof(ev),
	}
}

func pauseProof(ev Event) *RequiredProof {
	desc := "human approval for host-code-execution effect outside declared envelope"
	switch ev.Effect {
	case EffectNetEgress:
		desc = "human approval for network-egress effect outside declared envelope"
	case EffectCanaryAccess:
		desc = "human approval for canary-access effect outside declared envelope"
	}
	return &RequiredProof{
		Type:        "fresh_authorization",
		Description: desc,
	}
}

func envelopeTransition(before, after string) string {
	return before + " -> " + after
}
