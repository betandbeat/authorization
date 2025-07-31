package authorization

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluator_Evaluate(t *testing.T) {
	// Fixed time for consistent "at" in requests.
	now := time.Now()

	// Define common principals, actions, and resources to reuse in tests.
	const (
		user1      Principal = "user:1"
		readAction Action    = "read"
		doc1       Resource  = "document:1"
	)

	testCases := []struct {
		name           string
		statements     []Statement
		request        Request
		expectedEffect Effect
		expectedMsg    string
		expectErr      bool
	}{
		{
			name:           "Default Deny: No statements match",
			statements:     []Statement{},
			request:        Request{Principal: user1, Action: readAction, Resource: doc1},
			expectedEffect: EffectDeny,
			expectedMsg:    "no applicable statements found, access denied by default",
		},
		{
			name: "Simple Allow: Matching allow statement grants access",
			statements: []Statement{
				{ID: "allow-read", Effect: EffectAllow, Principals: []Principal{user1}, Actions: []Action{readAction}, Resources: []Resource{doc1}},
			},
			request:        Request{Principal: user1, Action: readAction, Resource: doc1},
			expectedEffect: EffectAllow,
			expectedMsg:    `allowed by statement "allow-read"`,
		},
		{
			name: "Simple Deny: Matching deny statement revokes access",
			statements: []Statement{
				{ID: "deny-read", Effect: EffectDeny, Principals: []Principal{user1}, Actions: []Action{readAction}, Resources: []Resource{doc1}},
			},
			request:        Request{Principal: user1, Action: readAction, Resource: doc1},
			expectedEffect: EffectDeny,
			expectedMsg:    `denied by statement "deny-read"`,
		},
		{
			name: "Deny Overrides Allow: Deny statement takes precedence",
			statements: []Statement{
				{ID: "allow-read", Effect: EffectAllow, Principals: []Principal{user1}, Actions: []Action{readAction}, Resources: []Resource{doc1}},
				{ID: "deny-read", Effect: EffectDeny, Principals: []Principal{user1}, Actions: []Action{readAction}, Resources: []Resource{doc1}},
			},
			request:        Request{Principal: user1, Action: readAction, Resource: doc1},
			expectedEffect: EffectDeny,
			expectedMsg:    `denied by statement "deny-read"`,
		},
		{
			name: "Allow with Matching Condition: Condition is met",
			statements: []Statement{
				{
					ID:         "allow-local",
					Effect:     EffectAllow,
					Principals: []Principal{user1},
					Actions:    []Action{readAction},
					Resources:  []Resource{doc1},
					Conditions: []Condition{{Name: "IsLocal", Expression: `context.Request.IP == "127.0.0.1"`}},
				},
			},
			request: Request{
				Principal: user1, Action: readAction, Resource: doc1,
				Context: Context{Request: struct {
					At        time.Time `json:"at"`
					IP        string    `json:"ip"`
					UserAgent string    `json:"user_agent"`
				}{At: now, IP: "127.0.0.1"}}},
			expectedEffect: EffectAllow,
			expectedMsg:    `allowed by statement "allow-local"`,
		},
		{
			name: "Allow with Non-Matching Condition: Condition is not met",
			statements: []Statement{
				{
					ID:         "allow-local",
					Effect:     EffectAllow,
					Principals: []Principal{user1},
					Actions:    []Action{readAction},
					Resources:  []Resource{doc1},
					Conditions: []Condition{{Name: "IsLocal", Expression: `context.Request.IP == "127.0.0.1"`}},
				},
			},
			request: Request{
				Principal: user1, Action: readAction, Resource: doc1,
				Context: Context{Request: struct {
					At        time.Time `json:"at"`
					IP        string    `json:"ip"`
					UserAgent string    `json:"user_agent"`
				}{At: now, IP: "192.168.1.1"}}},
			expectedEffect: EffectDeny,
			expectedMsg:    "no matching statement found, access denied by default",
		},
		{
			name: "Deny with Matching Condition: Condition is met, access denied",
			statements: []Statement{
				{
					ID:         "deny-remote",
					Effect:     EffectDeny,
					Principals: []Principal{user1},
					Actions:    []Action{readAction},
					Resources:  []Resource{doc1},
					Conditions: []Condition{{Name: "IsRemote", Expression: `context.Request.IP != "127.0.0.1"`}},
				},
			},
			request: Request{
				Principal: user1, Action: readAction, Resource: doc1,
				Context: Context{Request: struct {
					At        time.Time `json:"at"`
					IP        string    `json:"ip"`
					UserAgent string    `json:"user_agent"`
				}{At: now, IP: "192.168.1.1"}}},
			expectedEffect: EffectDeny,
			expectedMsg:    `denied by statement "deny-remote"`,
		},
		{
			name: "Deny with Non-Matching Condition: Deny is ignored, allow proceeds",
			statements: []Statement{
				{ID: "allow-read", Effect: EffectAllow, Principals: []Principal{user1}, Actions: []Action{readAction}, Resources: []Resource{doc1}},
				{
					ID:         "deny-remote",
					Effect:     EffectDeny,
					Principals: []Principal{user1},
					Actions:    []Action{readAction},
					Resources:  []Resource{doc1},
					Conditions: []Condition{{Name: "IsRemote", Expression: `context.Request.IP != "127.0.0.1"`}},
				},
			},
			request: Request{
				Principal: user1, Action: readAction, Resource: doc1,
				Context: Context{Request: struct {
					At        time.Time `json:"at"`
					IP        string    `json:"ip"`
					UserAgent string    `json:"user_agent"`
				}{At: now, IP: "127.0.0.1"}}},
			expectedEffect: EffectAllow,
			expectedMsg:    `allowed by statement "allow-read"`,
		},
		{
			name: "Deny on Condition Error: Safer to deny if condition fails",
			statements: []Statement{
				{
					ID:         "deny-bad-cond",
					Effect:     EffectDeny,
					Principals: []Principal{user1},
					Actions:    []Action{readAction},
					Resources:  []Resource{doc1},
					Conditions: []Condition{{Name: "BadCond", Expression: `invalid syntax`}},
				},
			},
			request:        Request{Principal: user1, Action: readAction, Resource: doc1},
			expectedEffect: EffectDeny,
			expectedMsg:    "failed to evaluate condition for deny statement \"deny-bad-cond\": failed to evaluate condition \"BadCond\": unexpected token",
		},
		{
			name: "Allow Skips on Condition Error: Non-matching, default deny",
			statements: []Statement{
				{
					ID:         "allow-bad-cond",
					Effect:     EffectAllow,
					Principals: []Principal{user1},
					Actions:    []Action{readAction},
					Resources:  []Resource{doc1},
					Conditions: []Condition{{Name: "BadCond", Expression: `invalid syntax`}},
				},
			},
			request:        Request{Principal: user1, Action: readAction, Resource: doc1},
			expectedEffect: EffectDeny,
			expectedMsg:    "no matching statement found, access denied by default",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			storage := NewInMemoryStorage()
			for _, stmt := range tc.statements {
				err := storage.SaveStatement(stmt)
				require.NoError(t, err, "Failed to save statement")
			}

			evaluator := NewEvaluator(storage)
			response, err := evaluator.Evaluate(tc.request)

			if tc.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expectedEffect, response.Effect, "Unexpected effect")
			assert.Contains(t, response.Message, tc.expectedMsg, "Unexpected message")

			// Check decider is set when expected
			isDefaultDeny := response.Message == "no matching statement found, access denied by default" ||
				response.Message == "no applicable statements found, access denied by default"
			if isDefaultDeny {
				assert.Nil(t, response.Decider, "Decider should be nil for default deny")
			} else {
				assert.NotNil(t, response.Decider, "Decider should be set for allow/deny decisions")
			}
		})
	}
}

// TestEvaluator_StorageError tests how the evaluator handles errors from the storage layer.
func TestEvaluator_StorageError(t *testing.T) {
	storage := &mockStorage{
		listStatementsErr: fmt.Errorf("database is down"),
	}
	evaluator := NewEvaluator(storage)

	_, err := evaluator.Evaluate(Request{Principal: "user:1"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list statements: database is down")
}

// mockStorage is a mock implementation of the Storage interface for testing error cases.
type mockStorage struct {
	listStatementsErr error
}

func (m *mockStorage) SaveStatement(statement Statement) error { return nil }
func (m *mockStorage) DeleteStatement(id string) error         { return nil }
func (m *mockStorage) GetStatement(id string) (*Statement, error) {
	return nil, nil
}
func (m *mockStorage) ListStatementsByPrincipal(principal Principal) ([]Statement, error) {
	if m.listStatementsErr != nil {
		return nil, m.listStatementsErr
	}
	return []Statement{}, nil
}

// TestEvaluator_PatternMatching tests glob pattern matching for principals, actions, and resources
func TestEvaluator_PatternMatching(t *testing.T) {
	now := time.Now()

	testCases := []struct {
		name           string
		statements     []Statement
		request        Request
		expectedEffect Effect
		expectedMsg    string
	}{
		{
			name: "Principal Wildcard Pattern: user:* matches user:123",
			statements: []Statement{
				{
					ID:         "allow-all-users",
					Effect:     EffectAllow,
					Principals: []Principal{"user:*"},
					Actions:    []Action{"read"},
					Resources:  []Resource{"document:1"},
				},
			},
			request:        Request{Principal: "user:123", Action: "read", Resource: "document:1"},
			expectedEffect: EffectAllow,
			expectedMsg:    `allowed by statement "allow-all-users"`,
		},
		{
			name: "Action Wildcard Pattern: read.* matches read.documents",
			statements: []Statement{
				{
					ID:         "allow-read-actions",
					Effect:     EffectAllow,
					Principals: []Principal{"user:1"},
					Actions:    []Action{"read.*"},
					Resources:  []Resource{"document:1"},
				},
			},
			request:        Request{Principal: "user:1", Action: "read.documents", Resource: "document:1"},
			expectedEffect: EffectAllow,
			expectedMsg:    `allowed by statement "allow-read-actions"`,
		},
		{
			name: "Resource Wildcard Pattern: documents/* matches documents/sensitive",
			statements: []Statement{
				{
					ID:         "allow-all-docs",
					Effect:     EffectAllow,
					Principals: []Principal{"user:1"},
					Actions:    []Action{"read"},
					Resources:  []Resource{"documents/*"},
				},
			},
			request:        Request{Principal: "user:1", Action: "read", Resource: "documents/sensitive"},
			expectedEffect: EffectAllow,
			expectedMsg:    `allowed by statement "allow-all-docs"`,
		},
		{
			name: "Hierarchical Resource Pattern: folders/*/documents/* matches nested structure",
			statements: []Statement{
				{
					ID:         "allow-folder-docs",
					Effect:     EffectAllow,
					Principals: []Principal{"user:1"},
					Actions:    []Action{"read"},
					Resources:  []Resource{"folders/*/documents/*"},
				},
			},
			request:        Request{Principal: "user:1", Action: "read", Resource: "folders/123/documents/456"},
			expectedEffect: EffectAllow,
			expectedMsg:    `allowed by statement "allow-folder-docs"`,
		},
		{
			name: "Multiple Wildcards: service:* with action ledger.* on resource transactions/*",
			statements: []Statement{
				{
					ID:         "allow-services-ledger",
					Effect:     EffectAllow,
					Principals: []Principal{"service:*"},
					Actions:    []Action{"ledger.*"},
					Resources:  []Resource{"transactions/*"},
				},
			},
			request:        Request{Principal: "service:payment", Action: "ledger.create", Resource: "transactions/tx123"},
			expectedEffect: EffectAllow,
			expectedMsg:    `allowed by statement "allow-services-ledger"`,
		},
		{
			name: "Pattern Mismatch: user:* doesn't match admin:123",
			statements: []Statement{
				{
					ID:         "allow-users-only",
					Effect:     EffectAllow,
					Principals: []Principal{"user:*"},
					Actions:    []Action{"read"},
					Resources:  []Resource{"document:1"},
				},
			},
			request:        Request{Principal: "admin:123", Action: "read", Resource: "document:1"},
			expectedEffect: EffectDeny,
			expectedMsg:    "no applicable statements found, access denied by default",
		},
		{
			name: "Deny Pattern Override: deny service:* overrides allow user:*",
			statements: []Statement{
				{
					ID:         "allow-all-users",
					Effect:     EffectAllow,
					Principals: []Principal{"*"},
					Actions:    []Action{"read"},
					Resources:  []Resource{"document:1"},
				},
				{
					ID:         "deny-services",
					Effect:     EffectDeny,
					Principals: []Principal{"service:*"},
					Actions:    []Action{"read"},
					Resources:  []Resource{"document:1"},
				},
			},
			request:        Request{Principal: "service:payment", Action: "read", Resource: "document:1"},
			expectedEffect: EffectDeny,
			expectedMsg:    `denied by statement "deny-services"`,
		},
		{
			name: "Complex Pattern: admin users can perform any action on secure resources",
			statements: []Statement{
				{
					ID:         "admin-secure-access",
					Effect:     EffectAllow,
					Principals: []Principal{"user:admin*"},
					Actions:    []Action{"*"},
					Resources:  []Resource{"secure/**"},
				},
			},
			request:        Request{Principal: "user:admin123", Action: "delete", Resource: "secure/vault/data"},
			expectedEffect: EffectAllow,
			expectedMsg:    `allowed by statement "admin-secure-access"`,
		},
		{
			name: "Pattern with Conditions: Only local admin access to admin panel",
			statements: []Statement{
				{
					ID:         "admin-local-only",
					Effect:     EffectAllow,
					Principals: []Principal{"admin:*"},
					Actions:    []Action{"admin.*"},
					Resources:  []Resource{"panel/*"},
					Conditions: []Condition{{Name: "IsLocal", Expression: `context.Request.IP == "127.0.0.1"`}},
				},
			},
			request: Request{
				Principal: "admin:superuser",
				Action:    "admin.settings",
				Resource:  "panel/settings",
				Context: Context{Request: struct {
					At        time.Time `json:"at"`
					IP        string    `json:"ip"`
					UserAgent string    `json:"user_agent"`
				}{At: now, IP: "127.0.0.1"}},
			},
			expectedEffect: EffectAllow,
			expectedMsg:    `allowed by statement "admin-local-only"`,
		},
		{
			name: "Character Class Pattern: user:[0-9]* matches numeric user IDs",
			statements: []Statement{
				{
					ID:         "allow-numeric-users",
					Effect:     EffectAllow,
					Principals: []Principal{"user:[0-9]*"},
					Actions:    []Action{"read"},
					Resources:  []Resource{"profile:*"},
				},
			},
			request:        Request{Principal: "user:12345", Action: "read", Resource: "profile:basic"},
			expectedEffect: EffectAllow,
			expectedMsg:    `allowed by statement "allow-numeric-users"`,
		},
		{
			name: "Single Character Pattern: temp? matches temp1, temp2, etc.",
			statements: []Statement{
				{
					ID:         "allow-temp-users",
					Effect:     EffectAllow,
					Principals: []Principal{"temp?"},
					Actions:    []Action{"read"},
					Resources:  []Resource{"temp/*"},
				},
			},
			request:        Request{Principal: "temp1", Action: "read", Resource: "temp/file1"},
			expectedEffect: EffectAllow,
			expectedMsg:    `allowed by statement "allow-temp-users"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			storage := NewInMemoryStorage()
			for _, stmt := range tc.statements {
				err := storage.SaveStatement(stmt)
				require.NoError(t, err, "Failed to save statement")
			}

			evaluator := NewEvaluator(storage)
			response, err := evaluator.Evaluate(tc.request)

			require.NoError(t, err)
			assert.Equal(t, tc.expectedEffect, response.Effect, "Unexpected effect")
			assert.Contains(t, response.Message, tc.expectedMsg, "Unexpected message")

			// Check decider is set appropriately
			isDefaultDeny := response.Message == "no matching statement found, access denied by default" ||
				response.Message == "no applicable statements found, access denied by default"
			if isDefaultDeny {
				assert.Nil(t, response.Decider, "Decider should be nil for default deny")
			} else {
				assert.NotNil(t, response.Decider, "Decider should be set for allow/deny decisions")
			}
		})
	}
}
