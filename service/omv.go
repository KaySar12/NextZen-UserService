package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/IceWhaleTech/CasaOS-UserService/service/model"
)

type OMVService interface {
	LoginSession(userName string, password string) string
	Logout()
	GetUser(username string) string
	SetUser(m model.UserDBModel) model.UserDBModel
	ApplyChange()
}
type omvService struct {
}

// LoginSession implements OMVService.
func (o *omvService) LoginSession(userName string, password string) string {
	panic("unimplemented")
}

func LoginSession(username string, password string) string {
	postBody, _ := json.Marshal(map[string]interface{}{
		"service": "session",
		"method":  "login",
		"params": map[string]string{
			"username": username,
			"password": password,
		},
	})
	responseBody := bytes.NewBuffer(postBody)
	response, err := http.Post("http://10.0.0.4:1081/rpc.php", "application/json", responseBody)
	if err != nil {
		fmt.Print(err.Error())
		os.Exit(1)
	}
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	return string(responseData)
}
func (o *omvService) Logout() {
	// Implement logout logic here
}

func (o *omvService) GetUser(username string) string {
	postBody, _ := json.Marshal(map[string]interface{}{
		"service": "UserMgmt",
		"method":  "getUser",
		"params": map[string]string{
			"name": username,
		},
	})
	responseBody := bytes.NewBuffer(postBody)
	response, err := http.Post("http://10.0.0.4:1081/rpc.php", "application/json", responseBody)
	if err != nil {
		fmt.Print(err.Error())
		os.Exit(1)
	}
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	return string(responseData)
}

func (o *omvService) SetUser(m model.UserDBModel) model.UserDBModel {
	// Implement SetUser logic here
	return m // Assuming m is the modified user
}

func (o *omvService) ApplyChange() {
	// Implement ApplyChange logic here
}

func NewOMVService() OMVService {
	return &omvService{}
}
