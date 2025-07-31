package iam_actions

import "github.com/betandbeat/authorization"

func All() []authorization.Action {
	return []authorization.Action{
		SIGNUP,
		SIGNIN,
		DELETE_USER,
		UPDATE_USER,
		GET_USER,
		SEARCH_USERS,
	}
}

const (
	SIGNUP       authorization.Action = "iam:SignUp"
	SIGNIN       authorization.Action = "iam:SignIn"
	DELETE_USER  authorization.Action = "iam:DeleteUser"
	UPDATE_USER  authorization.Action = "iam:UpdateUser"
	GET_USER     authorization.Action = "iam:GetUser"
	SEARCH_USERS authorization.Action = "iam:SearchUsers"
)
