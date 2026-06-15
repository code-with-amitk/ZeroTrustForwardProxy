// Package inspector performs lightweight payload inspection for DLP controls.
//
// Architecture fit:
// - The proxy invokes this package before forwarding requests and responses.
// - Violations produced here are used by policy enforcement to block traffic.
//
// Key responsibilities:
// - Scan payload bytes for sensitive-data signatures.
// - Return structured violation records.
// - Preserve request/response bodies after inspection.
//
// Design decisions:
// - Regex-based detection keeps implementation simple and deterministic.
package inspector

import (
	"bytes"
	"io"
	"net/http"
	"regexp"

	"go.uber.org/zap"
)

type Violation struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

// Inspector encapsulates DLP matching rules and size constraints.
type Inspector struct {
	logger   *zap.SugaredLogger
	maxBytes int64
	ccRegex  *regexp.Regexp
	keyRegex *regexp.Regexp
}

// New constructs an Inspector with compiled detection patterns.
// Inputs:
// - maxBytes: maximum body bytes to inspect per message.
func New(maxBytes int64) *Inspector {
	return &Inspector{
		maxBytes: maxBytes,

		// Compile credit card-like detector once
		ccRegex: regexp.MustCompile(`\b(?:\d[ -]*?){13,16}\b`),

		// Compile secret detector for key=value style API key/token disclosures.
		keyRegex: regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret|token)\s*[:=]\s*[A-Za-z0-9_\-]{8,}\b`),
	}
}

// InspectRequest scans request body for DLP violations while preserving the
// remainder of the stream for upstream transmission.
func (i *Inspector) InspectRequest(r *http.Request) ([]Violation, int64, error) {
	if r.Body == nil {
		return nil, 0, nil
	}

	viol, bytesInspected, restored, err := inspectAndPreserve(r.Body, i.maxBytes, i.inspectBytes)
	if err != nil {
		return nil, 0, err
	}
	r.Body = restored
	return viol, bytesInspected, nil
}

// InspectResponse scans upstream response body for DLP violations while
// preserving the remainder of the body stream for downstream delivery.
func (i *Inspector) InspectResponse(resp *http.Response) ([]Violation, int64, error) {
	if resp == nil || resp.Body == nil {
		return nil, 0, nil
	}

	viol, bytesInspected, restored, err := inspectAndPreserve(resp.Body, i.maxBytes, i.inspectBytes)
	if err != nil {
		return nil, 0, err
	}
	resp.Body = restored
	return viol, bytesInspected, nil
}

// Apply all DLP detectors to input bytes.
func (i *Inspector) inspectBytes(b []byte) []Violation {

	var out []Violation

	// Check for credit-card-like sequences in payload.
	if i.ccRegex.Match(b) {
		out = append(out, Violation{
			Type:   "credit_card",
			Detail: "potential credit card number detected",
		})
	}

	// Check for likely secrets such as API keys and tokens.
	if i.keyRegex.Match(b) {
		out = append(out, Violation{
			Type:   "secret",
			Detail: "potential API key/secret detected",
		})
	}
	return out
}

// Recreate a fresh body reader.
func inspectAndPreserve(body io.ReadCloser, max int64, inspect func([]byte) []Violation) ([]Violation, int64, io.ReadCloser, error) {
	if body == nil {
		return nil, 0, nil, nil
	}

	lr := &io.LimitedReader{R: body, N: max}
	buf, err := io.ReadAll(lr)
	if err != nil {
		_ = body.Close()
		return nil, 0, nil, err
	}

	preserved := &preservingBody{
		Reader: io.MultiReader(bytes.NewReader(buf), body),
		Closer: body,
	}

	return inspect(buf), int64(len(buf)), preserved, nil
}

type preservingBody struct {
	io.Reader
	io.Closer
}

func (p *preservingBody) Read(b []byte) (int, error) {
	return p.Reader.Read(b)
}
