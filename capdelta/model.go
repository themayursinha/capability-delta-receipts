package capdelta

// Event types that make up a trajectory.
const (
	EventDeclare = "declare"
	EventFile    = "file"
	EventBuild   = "build"
	EventRuntime = "runtime"
	EventRequest = "request"
)

// Runtime markers observed in target process output.
const (
	MarkerMemoryCorruption = "memory_corruption"
	MarkerSandboxEscape    = "sandbox_escape"
)

// Requested effects. HOST_EXEC, NET_EGRESS, and canary access lie outside
// the declared envelope; every other primitive stays inside it.
const (
	EffectHostExec     = "host_exec"
	EffectNetEgress    = "net_egress"
	EffectCanaryAccess = "canary_access"
)

// Signal kinds. Evidence levels are declared_only < artifact <
// runtime_marker < boundary_request. Only boundary_request kinds can
// trigger PAUSE; kinds 1–5 build deltas and are always recorded.
const (
	SignalDeclaredIntent   = "reasoning.declared_intent"
	SignalPoCCreated       = "artifact.poc_created"
	SignalBuildArtifact    = "artifact.build_artifact"
	SignalMemoryCorruption = "runtime.memory_corruption_marker"
	SignalSandboxEscape    = "runtime.sandbox_escape_marker"
	SignalHostExec         = "boundary.request_host_exec"
	SignalRequestEgress    = "boundary.request_egress"
	SignalCanaryAccess     = "boundary.canary_access"
)

// Evidence levels. Declared intent alone never confirms a capability (D1/CD-3).
const (
	EvidenceDeclaredOnly    = "declared_only"
	EvidenceArtifact        = "artifact"
	EvidenceRuntimeMarker   = "runtime_marker"
	EvidenceBoundaryRequest = "boundary_request"
)

// Capability lattice in fixed partial-order. Arrays on receipts are always
// emitted in this order (CD-6). read_sandbox_mem is the baseline (held
// from the start, never a delta, never a pause trigger). host_exec and
// net_egress are lattice capabilities whose effects lie outside the
// envelope; canary access is a boundary effect, not a lattice capability.
// Host exec, network egress, and canary access are the effects that pause.
const (
	CapReadSandboxMem = "read_sandbox_mem"
	CapOOBRead        = "oob_read"
	CapOOBWrite       = "oob_write"
	CapHeapEscape     = "heap_escape"
	CapNativeExec     = "native_exec"
	CapHostExec       = "host_exec"
	CapNetEgress      = "net_egress"
)

// lattice is the deterministic emission order for capability arrays.
var lattice = []string{
	CapReadSandboxMem,
	CapOOBRead,
	CapOOBWrite,
	CapHeapEscape,
	CapNativeExec,
	CapHostExec,
	CapNetEgress,
}

// Authorization decisions. PAUSE is an authorization result, not a process failure.
const (
	DecisionAllow = "ALLOW"
	DecisionPause = "PAUSE_REQUIRE_NEW_PROOF"
)

// Envelope states.
const (
	EnvelopeHigh             = "HIGH"
	EnvelopeBoundaryCrossing = "BOUNDARY_CROSSING"
)

// CapabilityConfirmation values. Declared intent yields provisional only.
const (
	ConfirmationProvisional = "provisional"
	ConfirmationConfirmed   = "confirmed"
)

// ReasonEffectOutsideEnvelope is the only pause reason in this slice.
// Heuristics never decide a pause (CD-1/CD-2).
const ReasonEffectOutsideEnvelope = "effect_outside_declared_envelope"

const (
	receiptVersion     = 1
	receiptVersionTree = 2
)

// Envelope is the declared target/network/host boundary.
type Envelope struct {
	DeclaredTarget  string `json:"declared_target"`
	DeclaredNetwork string `json:"declared_network"`
	DeclaredHost    string `json:"declared_host"`
}

// DeclaredAuthority is recorded on every receipt (acceptance field).
type DeclaredAuthority struct {
	Target  string `json:"target"`
	Network string `json:"network"`
	Host    string `json:"host"`
	Intent  string `json:"intent"`
}

// Signal is a typed observation extracted from one event.
type Signal struct {
	Kind          string `json:"kind"`
	Observation   string `json:"observation"`
	EvidenceLevel string `json:"evidence_level"`
	SourceDigest  string `json:"source_digest"`
}

// Event is one step in a scripted trajectory.
type Event struct {
	Type         string `json:"type"`
	StepID       int    `json:"step_id"`
	Target       string `json:"target"`
	EffectTarget string `json:"effect_target"`
	Marker       string `json:"marker"`
	Observation  string `json:"observation"`
	Digest       string `json:"digest"`
	Path         string `json:"path"`
	Effect       string `json:"effect"`
	Primitive    string `json:"primitive"`
}

// Trajectory is the ordered input to Evaluate.
type Trajectory struct {
	SessionID         string            `json:"session_id"`
	Envelope          Envelope          `json:"envelope"`
	DeclaredAuthority DeclaredAuthority `json:"declared_authority"`
	Events            []Event           `json:"events"`
	Canary            Canary            `json:"canary"`
	EphemeralCanary   Canary            `json:"ephemeral_canary"`
}

// SearchBudget is the hard CD-7 ceiling snapshot. Depth, branching, and
// total explored nodes are fail-closed limits, not heuristics.
type SearchBudget struct {
	MaxDepth     int `json:"max_depth"`
	MaxBranching int `json:"max_branching"`
	MaxNodes     int `json:"max_nodes"`
}

// Branch is one explored-but-pruned side path of a SearchTrajectory.
type Branch struct {
	BranchID     string  `json:"branch_id"`
	ParentStepID int     `json:"parent_step_id"`
	ReasonPruned string  `json:"reason_pruned"`
	Events       []Event `json:"events"`
}

// SearchTrajectory is the tree-search input to EvaluateSearch. Existing
// linear Trajectory values stay valid and unchanged.
type SearchTrajectory struct {
	SessionID         string            `json:"session_id"`
	Envelope          Envelope          `json:"envelope"`
	DeclaredAuthority DeclaredAuthority `json:"declared_authority"`
	Budget            SearchBudget      `json:"budget"`
	Events            []Event           `json:"events"`
	Branches          []Branch          `json:"branches"`
	Canary            Canary            `json:"canary"`
	EphemeralCanary   Canary            `json:"ephemeral_canary"`
}

// Canary is an out-of-envelope file. Evaluate never touches it (D3/CD-2).
type Canary struct {
	Path    string `json:"path"`
	Touched bool   `json:"touched"`
}

// RequiredProof names the fresh authorization demanded on PAUSE.
// Null on ALLOW.
type RequiredProof struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

// EnvelopeState is the HIGH / BOUNDARY_CROSSING marker on a receipt.
type EnvelopeState struct {
	State string `json:"state"`
}

// ProvisionalCapability is the machine-readable declared primitive when
// declared intent has not been confirmed (D1/CD-3). Nil (field omitted)
// when no primitive is declared.
type ProvisionalCapability struct {
	Capability    string `json:"capability"`
	Confirmation  string `json:"confirmation"`
	EvidenceLevel string `json:"evidence_level"`
}

// Receipt is one canonical hash-linked JSONL object. Field declaration
// order is the JSON field order (CD-6).
type Receipt struct {
	ReceiptVersion            int                    `json:"receipt_version"`
	SessionID                 string                 `json:"session_id"`
	StepID                    int                    `json:"step_id"`
	DeclaredAuthority         DeclaredAuthority      `json:"declared_authority"`
	Signals                   []Signal               `json:"signals"`
	CapabilityBefore          []string               `json:"capability_before"`
	CapabilityDelta           []string               `json:"capability_delta"`
	CapabilityAfter           []string               `json:"capability_after"`
	ObservedCapability        string                 `json:"observed_capability"`
	NominalPermissionsChanged bool                   `json:"nominal_permissions_changed"`
	EffectiveAuthorityChanged bool                   `json:"effective_authority_changed"`
	EnvelopeBefore            EnvelopeState          `json:"envelope_before"`
	EnvelopeAfter             EnvelopeState          `json:"envelope_after"`
	EnvelopeTransition        string                 `json:"envelope_transition"`
	Decision                  string                 `json:"decision"`
	Reason                    string                 `json:"reason"`
	RequiredProof             *RequiredProof         `json:"required_proof"`
	PrevHash                  string                 `json:"prev_hash"`
	Hash                      string                 `json:"hash"`
	BranchID                  *jsonNullString        `json:"branch_id,omitempty"`
	NodeCount                 int                    `json:"node_count,omitempty"`
	SearchBudget              *SearchBudget          `json:"search_budget,omitempty"`
	ProvisionalCapability     *ProvisionalCapability `json:"provisional_capability,omitempty"`
	CapabilityConfirmation    string                 `json:"-"`
}

// Evaluation is the deterministic output of one trajectory.
type Evaluation struct {
	Receipts        []Receipt
	Canary          Canary
	EphemeralCanary Canary
}
