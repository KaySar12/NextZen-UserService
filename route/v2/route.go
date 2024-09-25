package v2

import codegen "github.com/KaySar12/NextZen-UserService/codegen/user_service"

type UserService struct{}

func NewUserService() codegen.ServerInterface {
	return &UserService{}
}
