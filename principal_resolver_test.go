package authorization

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrincipalResolver(t *testing.T) {
	// Create a principal resolver
	resolver := NewInMemoryPrincipalResolver()

	// Add some role mappings
	resolver.AddRoleMapping("users/mark", []Principal{
		"roles/moderator",
		"roles/analyst",
	})
	resolver.AddRoleMapping("users/alice", []Principal{
		"roles/admin",
	})

	// Test resolving principals for mark
	principals, err := resolver.ResolvePrincipals("users/mark")
	require.NoError(t, err, "unexpected error")

	expected := []Principal{"users/mark", "roles/moderator", "roles/analyst"}
	assert.Equal(t, expected, principals, "resolved principals for mark should match expected")

	// Test resolving for a user without roles
	principals, err = resolver.ResolvePrincipals("users/unknown")
	require.NoError(t, err, "unexpected error")
	assert.Equal(t, []Principal{"users/unknown"}, principals, "unknown user should only resolve to itself")

	// Test resolving for a role principal (should not expand)
	principals, err = resolver.ResolvePrincipals("roles/admin")
	require.NoError(t, err, "unexpected error")
	assert.Equal(t, []Principal{"roles/admin"}, principals, "role principal should only resolve to itself")
}

func TestExpandingEvaluator(t *testing.T) {
	// Set up storage with test statements
	storage := NewInMemoryStorage()

	// Statement allowing moderators to download invoices
	moderatorStatement := Statement{
		ID:         "allow-moderator-download",
		Effect:     EffectAllow,
		Principals: []Principal{"roles/moderator"},
		Actions:    []Action{"invoice.download"},
		Resources:  []Resource{"invoices/*"},
	}
	storage.SaveStatement(moderatorStatement)

	// Statement denying analysts from downloading specific invoice
	analystDenyStatement := Statement{
		ID:         "deny-analyst-specific",
		Effect:     EffectDeny,
		Principals: []Principal{"roles/analyst"},
		Actions:    []Action{"invoice.download"},
		Resources:  []Resource{"invoices/238423684"},
	}
	storage.SaveStatement(analystDenyStatement)

	// Create base evaluator
	baseEvaluator := NewEvaluator(storage)

	// Create principal resolver
	resolver := NewInMemoryPrincipalResolver()
	resolver.AddRoleMapping("users/mark", []Principal{
		"roles/moderator",
		"roles/analyst",
	})

	// Create expanding evaluator
	expandingEvaluator := NewExpandingEvaluator(baseEvaluator, resolver)

	// Test request: users/mark wants to download invoice 238423684
	request := Request{
		Principal: "users/mark",
		Action:    "invoice.download",
		Resource:  "invoices/238423684",
		Context: Context{
			Request: struct {
				At        time.Time `json:"at"`
				IP        string    `json:"ip"`
				UserAgent string    `json:"user_agent"`
			}{
				At:        time.Now(),
				IP:        "192.168.1.1",
				UserAgent: "test-agent",
			},
		},
	}

	// This should be denied because the analyst role is explicitly denied
	// even though the moderator role would allow it
	response, err := expandingEvaluator.Evaluate(request)
	require.NoError(t, err, "unexpected error")
	assert.Equal(t, EffectDeny, response.Effect, "expected deny")
	assert.NotNil(t, response.Decider, "decider should not be nil")
	assert.Equal(t, "principal_expansion:roles/analyst", *response.Decider, "expected decider to be 'principal_expansion:roles/analyst'")

	// Test with a different invoice that analyst isn't denied from
	request.Resource = "invoices/999999"

	response, err = expandingEvaluator.Evaluate(request)
	require.NoError(t, err, "unexpected error")
	assert.Equal(t, EffectAllow, response.Effect, "expected allow")
	assert.NotNil(t, response.Decider, "decider should not be nil")
	assert.Equal(t, "principal_expansion:roles/moderator", *response.Decider, "expected decider to be 'principal_expansion:roles/moderator'")
}

func TestExpandingEvaluatorWithoutRoles(t *testing.T) {
	// Set up storage without any matching statements
	storage := NewInMemoryStorage()

	// Create base evaluator
	baseEvaluator := NewEvaluator(storage)

	// Create principal resolver
	resolver := NewInMemoryPrincipalResolver()
	resolver.AddRoleMapping("users/mark", []Principal{
		"roles/moderator",
		"roles/analyst",
	})

	// Create expanding evaluator
	expandingEvaluator := NewExpandingEvaluator(baseEvaluator, resolver)

	// Test request: users/mark wants to download invoice
	request := Request{
		Principal: "users/mark",
		Action:    "invoice.download",
		Resource:  "invoices/238423684",
		Context: Context{
			Request: struct {
				At        time.Time `json:"at"`
				IP        string    `json:"ip"`
				UserAgent string    `json:"user_agent"`
			}{
				At:        time.Now(),
				IP:        "192.168.1.1",
				UserAgent: "test-agent",
			},
		},
	}

	// This should be denied because no statements match any of the expanded principals
	response, err := expandingEvaluator.Evaluate(request)
	require.NoError(t, err, "unexpected error")
	assert.Equal(t, EffectDeny, response.Effect, "expected deny")
	expectedMessage := "no matching statements found for any expanded principal, access denied by default"
	assert.Equal(t, expectedMessage, response.Message, "expected message to match")
}
