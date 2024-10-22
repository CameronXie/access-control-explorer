package authn

import "errors"

type HardcodedAuthenticator struct {
	users map[string]string
}

func (a *HardcodedAuthenticator) Authenticate(username, password string) (*User, error) {
	if a.users == nil {
		return nil, errors.New("authentication failed")
	}

	pass, ok := a.users[username]

	// This function is for demonstration purposes only and should not be used in production.
	// For production, please implement a secure authentication mechanism, such as
	// verifying credentials against a database and using proper hashing and salting techniques.
	if !ok || pass != password {
		return nil, errors.New("password mismatch")
	}

	return &User{Username: username}, nil
}

func NewHardcodedAuthenticator(users map[string]string) Authenticator {
	return &HardcodedAuthenticator{users: users}
}
