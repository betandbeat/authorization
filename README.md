# Authorization Engine

This package provides a flexible and powerful authorization engine inspired by policy-based access control systems like AWS IAM. It allows you to define who can do what on which resources, and under which conditions.

## Core Concepts

The authorization model is built around a few key concepts:

-   **`Statement`**: The core of a policy. It binds together principals, actions, resources, and conditions with an effect (`Allow` or `Deny`).
-   **`Principal`**: The "who". An entity that can perform an action on a resource (e.g., `user:123`, `service:abc`).
-   **`Action`**: The "what". The operation that the principal wants to perform (e.g., `documents:read`, `users:create`).
-   **`Resource`**: The "which". The object that the action is being performed on (e.g., `document:xyz`, `folder:confidential`).
-   **`Condition`**: Optional constraints that must be met for the statement to apply (e.g., the request must come from a specific IP address).
-   **`Effect`**: The outcome of the statement if it matches a request. It can be `Allow` or `Deny`.

Principals, Actions, and Resources support `*` and `**` glob-style pattern matching.

## Evaluation Logic

The `Evaluator` processes authorization requests against a set of statements. The logic is as follows:

1.  **Explicit Deny**: It first checks for any `Deny` statements that match the request. If a matching `Deny` statement is found, the request is immediately denied.
2.  **Explicit Allow**: If no `Deny` statements match, it then checks for any `Allow` statements that match the request. If a matching `Allow` statement is found, the request is allowed.
3.  **Default Deny**: If no statements match the request (neither `Deny` nor `Allow`), the request is denied by default.

## Storage

The engine is decoupled from the storage layer through the `Storage` interface. This interface defines how authorization statements are persisted and retrieved.

```go
type Storage interface {
    ListStatementsByPrincipal(principal Principal) ([]Statement, error)
}
```

It is the responsibility of the consumer of this package to provide a concrete implementation of the `Storage` interface that fits their application's needs (e.g., using a database like PostgreSQL, MySQL, or a key-value store like Redis).

An in-memory implementation (`NewInMemoryStorage`) is provided for basic use cases and for testing purposes. It is not recommended for production use as it is volatile and not scalable.

## Usage Example

```go
package main

import (
	"fmt"
	"time"

	"github.com/your-org/authorization"
)

func main() {
	// 1. Create a storage instance.
	// In a real application, you would use a persistent storage implementation.
	storage := authorization.NewInMemoryStorage()

	// 2. Define an authorization statement.
	statement := authorization.Statement{
		ID:         "allow-local-read",
		Effect:     authorization.EffectAllow,
		Principals: []authorization.Principal{"user:*"},
		Actions:    []authorization.Action{"documents:read"},
		Resources:  []authorization.Resource{"document:secret"},
		Conditions: []authorization.Condition{
			{
				Name:       "IsLocal",
				Expression: `context.Request.IP == "127.0.0.1"`,
			},
		},
	}
	storage.SaveStatement(statement)

	// 3. Create an evaluator.
	evaluator := authorization.NewEvaluator(storage)

	// 4. Build a request.
	req := authorization.Request{
		Principal: "user:123",
		Action:    "documents:read",
		Resource:  "document:secret",
		Context: authorization.Context{
			Request: struct {
				At        time.Time `json:"at"`
				IP        string    `json:"ip"`
				UserAgent string    `json:"user_agent"`
			}{
				At: time.Now(),
				IP: "127.0.0.1",
			},
		},
	}

	// 5. Evaluate the request.
	resp, err := evaluator.Evaluate(req)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Effect: %s, Message: %s\n", resp.Effect, resp.Message)
	// Output: Effect: allow, Message: allowed by statement "allow-local-read"
}
```

## Conditions

Conditions are expressed using the [expr](https://github.com/expr-lang/expr) language, which provides a safe and fast expression evaluation engine. The request object is available in the expression context, allowing for rich, attribute-based conditions.
