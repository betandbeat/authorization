package authorization

import (
	"time"

	"github.com/expr-lang/expr"
)

type Statement struct {
	ID          string      `json:"id"`
	Active      bool        `json:"active"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Effect      Effect      `json:"effect"`
	Principals  []Principal `json:"principals"`
	Actions     []Action    `json:"actions"`
	Resources   []Resource  `json:"resources"`
	Conditions  []Condition `json:"conditions,omitempty"`
	CreatedAt   time.Time   `json:"createdAt"`
	UpdatedAt   time.Time   `json:"updatedAt"`
	CreatedBy   string      `json:"createdBy"`
	UpdatedBy   string      `json:"updatedBy"`
}

type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

type Principal string

type Action string

type Resource string

type Condition struct {
	Name       string
	Expression string
}

type Context struct {
	Request struct {
		At        time.Time `json:"at"`
		IP        string    `json:"ip"`
		UserAgent string    `json:"user_agent"`
	}
}

type Request struct {
	Principal Principal `json:"principal" expr:"principal"`
	Action    Action    `json:"action" expr:"action"`
	Resource  Resource  `json:"resource" expr:"resource"`
	Context   Context   `json:"context" expr:"context"`
}

type Response struct {
	Effect  Effect  `json:"effect"`
	Message string  `json:"message"`
	Decider *string `json:"decider,omitempty"`
}

type Storage interface {
	ListStatementsByPrincipal(principal Principal) ([]Statement, error)
}

func (c *Condition) Evaluate(req Request) (bool, error) {
	program, err := expr.Compile(c.Expression)
	if err != nil {
		return false, err
	}
	res, err := expr.Run(program, req)
	if err != nil {
		return false, err
	}
	if result, ok := res.(bool); ok {
		return result, nil
	}
	return false, nil
}
