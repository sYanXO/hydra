package protocol

import (
	"encoding/json"
	"os"
	"testing"
)

type registerVector struct {
	Name              string          `json:"name"`
	Request           RegisterRequest `json:"request"`
	ExpectedCanonical string          `json:"expected_canonical"`
}

func TestRegisterVectorDeterministic(t *testing.T) {
	b, err := os.ReadFile("testdata/register_vector_v1.json")
	if err != nil {
		t.Fatalf("read vector file: %v", err)
	}
	var v registerVector
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("unmarshal vector: %v", err)
	}

	if got := v.Request.CanonicalString(); got != v.ExpectedCanonical {
		t.Fatalf("canonical mismatch\nwant: %q\n got: %q", v.ExpectedCanonical, got)
	}
	if err := v.Request.VerifySignature(); err != nil {
		t.Fatalf("verify signature failed: %v", err)
	}
}
