package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenAPIContractExists(t *testing.T) {
	p := filepath.Join("..", "..", "api", "openapi.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read openapi: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, "openapi: 3.1.0") {
		t.Fatalf("openapi version marker missing")
	}
	if !strings.Contains(s, "/users/register") || !strings.Contains(s, "/users/{id}/keys") {
		t.Fatalf("expected endpoint paths missing in openapi")
	}
}

func TestJSONSchemasParse(t *testing.T) {
	schemas := []string{
		filepath.Join("..", "..", "api", "schemas", "register-request.schema.json"),
		filepath.Join("..", "..", "api", "schemas", "error-envelope.schema.json"),
	}
	for _, p := range schemas {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read schema %s: %v", p, err)
		}
		var tmp map[string]any
		if err := json.Unmarshal(b, &tmp); err != nil {
			t.Fatalf("parse schema %s: %v", p, err)
		}
	}
}
