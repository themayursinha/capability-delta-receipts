// Command capdelta reads one trajectory JSON file and emits one
// deterministic JSONL receipt per event on stdout.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/themayursinha/capability-delta-receipts/capdelta"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "capdelta:", err)
		os.Exit(1)
	}
}

// run decodes one trajectory file, evaluates it, and writes one receipt
// per line. ALLOW and PAUSE are authorization results, not errors.
// Errors are reserved for usage, unreadable/malformed input, or encoding
// failures, and never leave a partial receipt on stdout.
func run(args []string, stdout io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: capdelta <trajectory.json>")
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	traj, err := decodeTrajectory(data)
	if err != nil {
		return err
	}
	eval := capdelta.Evaluate(traj)
	var buf bytes.Buffer
	for i := range eval.Receipts {
		line := eval.Receipts[i].Encode()
		if len(line) == 0 {
			return errors.New("receipt encoding failed")
		}
		if _, err := buf.Write(line); err != nil {
			return err
		}
	}
	_, err = stdout.Write(buf.Bytes())
	return err
}

// decodeTrajectory strictly decodes exactly one JSON object: a top-level
// array, scalar, or null is rejected, unknown fields are rejected, and
// trailing JSON after the object is rejected. A token-level shape pass
// runs first so the object is also rejected when it contains duplicate
// keys, case-variant or unknown field names, or null for a required
// field — cases encoding/json would otherwise accept silently.
func decodeTrajectory(data []byte) (capdelta.Trajectory, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return capdelta.Trajectory{}, errors.New("invalid trajectory JSON: expected a single JSON object")
	}
	if err := checkTrajectoryShape(bytes.NewReader(data)); err != nil {
		return capdelta.Trajectory{}, fmt.Errorf("invalid trajectory JSON: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var traj capdelta.Trajectory
	if err := dec.Decode(&traj); err != nil {
		return capdelta.Trajectory{}, fmt.Errorf("invalid trajectory JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return capdelta.Trajectory{}, errors.New("invalid trajectory JSON: trailing data after object")
		}
		return capdelta.Trajectory{}, fmt.Errorf("invalid trajectory JSON: %w", err)
	}
	return traj, nil
}

// jsonFieldKind describes the strict shape expected for one trajectory field.
type jsonFieldKind int

const (
	jsonFieldString     jsonFieldKind = iota // scalar string
	jsonFieldInt                             // JSON number bound to int
	jsonFieldBool                            // true or false
	jsonFieldEnvelope                        // envelope object
	jsonFieldAuthority                       // declared_authority object
	jsonFieldCanary                          // canary / ephemeral_canary object
	jsonFieldEventArray                      // array of event objects
)

// The trajectory schema is small and fixed, so the shape pass walks it
// explicitly. Null is never meaningful in a trajectory; object keys must
// be spelled exactly and may not repeat. These tables must stay in sync
// with capdelta.Trajectory and its nested input types.
var (
	trajectoryObjectFields = map[string]jsonFieldKind{
		"session_id":         jsonFieldString,
		"envelope":           jsonFieldEnvelope,
		"declared_authority": jsonFieldAuthority,
		"events":             jsonFieldEventArray,
		"canary":             jsonFieldCanary,
		"ephemeral_canary":   jsonFieldCanary,
	}
	envelopeObjectFields = map[string]jsonFieldKind{
		"declared_target":  jsonFieldString,
		"declared_network": jsonFieldString,
		"declared_host":    jsonFieldString,
	}
	authorityObjectFields = map[string]jsonFieldKind{
		"target":  jsonFieldString,
		"network": jsonFieldString,
		"host":    jsonFieldString,
		"intent":  jsonFieldString,
	}
	eventObjectFields = map[string]jsonFieldKind{
		"type":          jsonFieldString,
		"step_id":       jsonFieldInt,
		"target":        jsonFieldString,
		"effect_target": jsonFieldString,
		"marker":        jsonFieldString,
		"observation":   jsonFieldString,
		"digest":        jsonFieldString,
		"path":          jsonFieldString,
		"effect":        jsonFieldString,
		"primitive":     jsonFieldString,
	}
	canaryObjectFields = map[string]jsonFieldKind{
		"path":    jsonFieldString,
		"touched": jsonFieldBool,
	}
)

// checkTrajectoryShape token-scans one JSON object and rejects duplicate
// keys, case-variant or unknown field names, null values, and shape
// mismatches before any value is bound.
func checkTrajectoryShape(r io.Reader) error {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("expected a single JSON object")
	}
	if err := checkObject(dec, trajectoryObjectFields); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return errors.New("trailing data after object")
		}
		return err
	}
	return nil
}

// checkObject validates one JSON object against the exact field set: every
// key must be spelled exactly and appear at most once, and each value must
// match its expected kind (null is never accepted). It consumes the object
// including its closing delimiter.
func checkObject(dec *json.Decoder, fields map[string]jsonFieldKind) error {
	seen := make(map[string]bool, len(fields))
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return err
		}
		name := key.(string)
		if seen[name] {
			return fmt.Errorf("duplicate field %q", name)
		}
		seen[name] = true
		kind, ok := fields[name]
		if !ok {
			return fmt.Errorf("unknown field %q", name)
		}
		if err := checkValue(dec, kind); err != nil {
			return fmt.Errorf("field %q: %w", name, err)
		}
	}
	_, err := dec.Token() // consume the closing '}'
	return err
}

func checkValue(dec *json.Decoder, kind jsonFieldKind) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch kind {
	case jsonFieldString:
		if _, ok := tok.(string); !ok {
			return errors.New("expected a string")
		}
		return nil
	case jsonFieldInt:
		switch tok.(type) {
		case float64, json.Number:
			return nil
		default:
			return errors.New("expected a number")
		}
	case jsonFieldBool:
		if _, ok := tok.(bool); !ok {
			return errors.New("expected a boolean")
		}
		return nil
	case jsonFieldEnvelope:
		return checkNestedObject(dec, tok, envelopeObjectFields)
	case jsonFieldAuthority:
		return checkNestedObject(dec, tok, authorityObjectFields)
	case jsonFieldCanary:
		return checkNestedObject(dec, tok, canaryObjectFields)
	case jsonFieldEventArray:
		return checkObjectArray(dec, tok, eventObjectFields)
	}
	return nil
}

func checkNestedObject(dec *json.Decoder, tok json.Token, fields map[string]jsonFieldKind) error {
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("expected an object")
	}
	return checkObject(dec, fields)
}

func checkObjectArray(dec *json.Decoder, tok json.Token, fields map[string]jsonFieldKind) error {
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return errors.New("expected an array of objects")
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); !ok || d != '{' {
			return errors.New("expected an array of objects")
		}
		if err := checkObject(dec, fields); err != nil {
			return err
		}
	}
	_, err := dec.Token() // consume the closing ']'
	return err
}
