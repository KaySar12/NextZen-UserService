package service

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"

	model2 "github.com/IceWhaleTech/CasaOS-UserService/service/model"
)

type AuthentikService interface {
	HelloWorld() string
	GetUserInfo(accessToken string) model2.AuthentikUser
}

type authentikService struct {
}

func (a *authentikService) GetUserInfo(accessToken string) model2.AuthentikUser {
	bearer := "Bearer " + accessToken
	req, err := http.NewRequest("GET", "", bytes.NewBuffer(nil))
	req.Header.Set("Authorization", bearer)
	req.Header.Add("Accept", "application/json")
	client := &http.Client{}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		for key, val := range via[0].Header {
			req.Header[key] = val
		}
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error on response.\n[ERRO] -", err)
	} else {
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		fmt.Println(string(data))
	}

	return model2.AuthentikUser{}
}
func (a *authentikService) HelloWorld() string {
	return "Hello World!"
}
func NewAuthentikService() AuthentikService {
	return &authentikService{}
}
