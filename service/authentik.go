package service

type AuthentikService interface {
	HelloWorld() string
}

type authentikService struct {
}

func (a *authentikService) HelloWorld() string {
	return "Hello World!"
}
func NewAuthentikService() AuthentikService {
	return &authentikService{}
}
