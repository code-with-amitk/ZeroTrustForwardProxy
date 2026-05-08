// Package inspector tests DLP detector behavior on representative payloads.
//
// Architecture fit:
// - Ensures request inspection catches sensitive data patterns before forwarding.
//
// Key responsibilities:
// - Validate regex detections for credit-card-like and secret-like inputs.
package inspector

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestInspectorDetectsCCAndSecret validates that both configured detectors fire.
//
// Inputs:
// - Synthetic HTTP request with payload containing credit card and API key patterns.
//
// Outputs:
// - Test pass/fail based on number of detected violations.
//
// Side effects:
// - Consumes/restores request body through inspector pipeline.
func TestInspectorDetectsCCAndSecret(t *testing.T) {
	// Build inspector with bounded payload inspection size.
	i := New(1024)
	// Construct request carrying known sensitive patterns for positive detection.
	req, _ := http.NewRequest(http.MethodPost, "http://example.com", strings.NewReader("card=4111 1111 1111 1111 api_key=ABCD1234ZZZZ"))
	// Provide explicit body stream because inspector reads from Body.
	req.Body = io.NopCloser(strings.NewReader("card=4111 1111 1111 1111 api_key=ABCD1234ZZZZ"))
	// Execute request inspection to collect violation findings.
	viol, err := i.InspectRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	// Expect at least one match per detector class (card + secret).
	if len(viol) < 2 {
		t.Fatalf("expected >=2 violations, got %d", len(viol))
	}
}
