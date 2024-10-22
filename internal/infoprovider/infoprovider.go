package infoprovider

type InfoProvider interface {
	GetRoles(id string) ([]string, error)
}
