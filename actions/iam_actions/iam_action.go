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

var (
	SIGNUP       authorization.Action = authorization.NewAction("iam:SignUp", "Sign Up", "Allows a user to sign up for an account")
	SIGNIN       authorization.Action = authorization.NewAction("iam:SignIn", "Sign In", "Allows a user to sign in to their account")
	DELETE_USER  authorization.Action = authorization.NewAction("iam:DeleteUser", "Delete User", "Allows an admin to delete a user account")
	UPDATE_USER  authorization.Action = authorization.NewAction("iam:UpdateUser", "Update User", "Allows an admin to update a user account")
	GET_USER     authorization.Action = authorization.NewAction("iam:GetUser", "Get User", "Allows an admin to retrieve a user account")
	SEARCH_USERS authorization.Action = authorization.NewAction("iam:SearchUsers", "Search Users", "Allows an admin to search for user accounts")
)
