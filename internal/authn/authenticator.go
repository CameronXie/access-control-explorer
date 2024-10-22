package authn

type User struct {
	Username string `json:"username"`
}

type Authenticator interface {
	Authenticate(username, password string) (*User, error)
}
