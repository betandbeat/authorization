package actions

import (
	"github.com/betandbeat/authorization"
	"github.com/betandbeat/authorization/actions/iam_actions"
)

func AllActions() []authorization.Action {
	all := []authorization.Action{}
	all = append(all, iam_actions.All()...)
	return all
}
