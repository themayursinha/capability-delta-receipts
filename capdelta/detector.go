package capdelta

import "strings"

// Evaluate reduces a trajectory into one receipt per event, in order.
//
// D1/CD-3: declared intent alone is provisional and never a confirmed delta.
// D4: every claimed capability cites a signal at a matching evidence level.
// D2/D3: only the boundary predicate decides PAUSE; this evaluator never
// executes a boundary-crossing effect and never touches the canary.
func Evaluate(traj Trajectory) Evaluation {
	return evaluateTrajectory(traj, false)
}

// EvaluateUnguarded is the CD-4 confined counterfactual: the same
// trajectory processing without the pause gate. A boundary-crossing
// request still records the capability delta, but the effect reaches
// only the ephemeral container canary. The host canary stays untouched.
func EvaluateUnguarded(traj Trajectory) Evaluation {
	return evaluateTrajectory(traj, true)
}

func evaluateTrajectory(traj Trajectory, unguarded bool) Evaluation {
	eval := Evaluation{
		Receipts:        make([]Receipt, 0, len(traj.Events)),
		Canary:          Canary{Path: traj.Canary.Path, Touched: false},
		EphemeralCanary: Canary{Path: traj.EphemeralCanary.Path, Touched: false},
	}
	held := []string{CapReadSandboxMem}
	envelopeState := EnvelopeHigh
	prevHash := genesisPrevHash

	for _, ev := range traj.Events {
		r := evaluateEvent(traj, ev, held, envelopeState, false)
		r.PrevHash = prevHash
		_ = r.Encode()
		eval.Receipts = append(eval.Receipts, r)
		held = r.CapabilityAfter
		envelopeState = r.EnvelopeAfter.State
		prevHash = r.Hash

		if unguarded && reachesEphemeralCanary(ev) {
			eval.EphemeralCanary.Touched = true
		}
	}
	return eval
}

func reachesEphemeralCanary(ev Event) bool {
	switch ev.Effect {
	case EffectHostExec, EffectCanaryAccess:
		return true
	}
	return false
}

func evaluateEvent(traj Trajectory, ev Event, held []string, envelopeBefore string, attestOnly bool) Receipt {
	signals := extractSignals(ev)
	inEnv := effectInEnvelope(traj.Envelope, ev)
	delta := confirmedDelta(ev, signals, inEnv, held)
	var bound boundaryResult
	if attestOnly {
		// Pruned branches were not executed (CD-1/CD-2): record deltas
		// for attestation only; never PAUSE and never cross the envelope.
		bound = boundaryResult{
			Decision: DecisionAllow,
			After:    envelopeBefore,
		}
	} else {
		bound = applyBoundaryPredicate(traj.Envelope, ev, envelopeBefore)
	}

	before := cloneCaps(held)
	after := unionLattice(before, delta)
	observed := highestCapability(delta)
	if bound.Decision == DecisionPause && observed == "" {
		observed = requestedEffectCapability(ev)
	}

	confirmation := ConfirmationProvisional
	if len(delta) > 0 {
		confirmation = ConfirmationConfirmed
	}

	var provisional *ProvisionalCapability
	if ev.Type == EventDeclare && ev.Primitive != "" && len(delta) == 0 {
		provisional = &ProvisionalCapability{
			Capability:    ev.Primitive,
			Confirmation:  ConfirmationProvisional,
			EvidenceLevel: EvidenceDeclaredOnly,
		}
	}

	return Receipt{
		ReceiptVersion:            receiptVersion,
		SessionID:                 traj.SessionID,
		StepID:                    ev.StepID,
		DeclaredAuthority:         traj.DeclaredAuthority,
		Signals:                   signals,
		CapabilityBefore:          before,
		CapabilityDelta:           delta,
		CapabilityAfter:           after,
		ObservedCapability:        observed,
		NominalPermissionsChanged: false,
		EffectiveAuthorityChanged: len(delta) > 0 || bound.After == EnvelopeBoundaryCrossing,
		EnvelopeBefore:            EnvelopeState{State: envelopeBefore},
		EnvelopeAfter:             EnvelopeState{State: bound.After},
		EnvelopeTransition:        envelopeTransition(envelopeBefore, bound.After),
		Decision:                  bound.Decision,
		Reason:                    bound.Reason,
		RequiredProof:             bound.RequiredProof,
		ProvisionalCapability:     provisional,
		CapabilityConfirmation:    confirmation,
	}
}

// extractSignals maps one event onto the signals table. Unknown or
// weak observations produce no invented confirmation (fail closed).
func extractSignals(ev Event) []Signal {
	sig := Signal{
		Observation:  ev.Observation,
		SourceDigest: ev.Digest,
	}
	switch ev.Type {
	case EventDeclare:
		sig.Kind = SignalDeclaredIntent
		sig.EvidenceLevel = EvidenceDeclaredOnly
		return []Signal{sig}
	case EventFile:
		if isPoCPath(ev.Path) {
			sig.Kind = SignalPoCCreated
			sig.EvidenceLevel = EvidenceArtifact
			return []Signal{sig}
		}
	case EventBuild:
		sig.Kind = SignalBuildArtifact
		sig.EvidenceLevel = EvidenceArtifact
		return []Signal{sig}
	case EventRuntime:
		switch ev.Marker {
		case MarkerMemoryCorruption:
			sig.Kind = SignalMemoryCorruption
			sig.EvidenceLevel = EvidenceRuntimeMarker
			return []Signal{sig}
		case MarkerSandboxEscape:
			sig.Kind = SignalSandboxEscape
			sig.EvidenceLevel = EvidenceRuntimeMarker
			return []Signal{sig}
		}
	case EventRequest:
		switch ev.Effect {
		case EffectHostExec:
			sig.Kind = SignalHostExec
			sig.EvidenceLevel = EvidenceBoundaryRequest
			return []Signal{sig}
		case EffectNetEgress:
			sig.Kind = SignalRequestEgress
			sig.EvidenceLevel = EvidenceBoundaryRequest
			return []Signal{sig}
		case EffectCanaryAccess:
			sig.Kind = SignalCanaryAccess
			sig.EvidenceLevel = EvidenceBoundaryRequest
			return []Signal{sig}
		}
	}
	return []Signal{}
}

// confirmedDelta is D1/D4: a confirmed lattice primitive requires a
// non-declared signal at matching evidence. Declared intent and artifact
// construction never confirm. Runtime markers confirm bug A/B only when
// the effect target is in-envelope. Boundary requests confirm the
// requested out-of-envelope primitive (recorded, not executed).
func confirmedDelta(ev Event, signals []Signal, inEnv bool, held []string) []string {
	var add []string
	switch ev.Type {
	case EventRuntime:
		if !inEnv {
			break
		}
		switch ev.Marker {
		case MarkerMemoryCorruption:
			if hasSignalLevel(signals, SignalMemoryCorruption, EvidenceRuntimeMarker) {
				add = []string{CapOOBRead, CapOOBWrite}
			}
		case MarkerSandboxEscape:
			if hasSignalLevel(signals, SignalSandboxEscape, EvidenceRuntimeMarker) {
				add = []string{CapHeapEscape, CapNativeExec}
			}
		}
	case EventRequest:
		switch ev.Effect {
		case EffectHostExec:
			if hasSignalLevel(signals, SignalHostExec, EvidenceBoundaryRequest) {
				add = []string{CapHostExec}
			}
		case EffectNetEgress:
			if hasSignalLevel(signals, SignalRequestEgress, EvidenceBoundaryRequest) {
				add = []string{CapNetEgress}
			}
		}
	}
	return newlyHeld(add, held)
}

func isPoCPath(path string) bool {
	return strings.HasSuffix(path, ".js") ||
		strings.HasSuffix(path, ".wasm") ||
		strings.HasSuffix(path, ".py")
}

func hasSignalLevel(signals []Signal, kind, level string) bool {
	for _, s := range signals {
		if s.Kind == kind && s.EvidenceLevel == level {
			return true
		}
	}
	return false
}

func requestedEffectCapability(ev Event) string {
	switch ev.Effect {
	case EffectHostExec:
		return CapHostExec
	case EffectNetEgress:
		return CapNetEgress
	case EffectCanaryAccess:
		return EffectCanaryAccess
	}
	return ev.Effect
}
