package service

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	model2 "github.com/IceWhaleTech/CasaOS-UserService/service/model"
	"gorm.io/gorm"
)

type AuthentikService interface {
	GetUserInfo(accessToken string, baseURL string) (model2.AuthentikUser, error)
	GetUserApp(accessToken string, baseURL string) (model2.AuthentikApplication, error)
	CreateCredential(m model2.AuthentikCredentialsDBModel) model2.AuthentikCredentialsDBModel
	UpdateCredential(m model2.AuthentikCredentialsDBModel) model2.AuthentikCredentialsDBModel
	GetCredential(id int) model2.AuthentikCredentialsDBModel
}

type authentikService struct {
	db *gorm.DB
}

var (
	APICorePrefix = "/api/v3/core"
)

func (a *authentikService) CreateCredential(m model2.AuthentikCredentialsDBModel) model2.AuthentikCredentialsDBModel {
	a.db.Create(&m)
	return m
}
func (a *authentikService) UpdateCredential(m model2.AuthentikCredentialsDBModel) model2.AuthentikCredentialsDBModel {
	a.db.Model(&m).Where("id = ?", m.Id).Updates(m)
	return m
}
func (a *authentikService) GetCredential(id int) model2.AuthentikCredentialsDBModel {
	var m model2.AuthentikCredentialsDBModel
	a.db.Limit(1).Where("id = ?", id).First(&m)
	return m
}
func (a *authentikService) GetUserApp(accessToken string, baseURL string) (model2.AuthentikApplication, error) {
	bearer := "Bearer " + accessToken
	path := baseURL + APICorePrefix + "/applications/"
	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		return model2.AuthentikApplication{}, err
	}
	req.Header.Set("Authorization", bearer)
	req.Header.Add("Accept", "application/json")
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Always follow redirects
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error on request:", err)
		return model2.AuthentikApplication{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Println("HTTP error:", resp.Status)
		return model2.AuthentikApplication{}, fmt.Errorf("HTTP error: %s", resp.Status)
	}

	var app model2.AuthentikApplication
	if err := json.NewDecoder(resp.Body).Decode(&app); err != nil {
		log.Println("Error decoding response:", err)
		return model2.AuthentikApplication{}, err
	}

	return app, nil

}
func (a *authentikService) GetUserInfo(accessToken string, baseURL string) (model2.AuthentikUser, error) {
	bearer := "Bearer " + accessToken
	path := baseURL + APICorePrefix + "/users/me/"
	req, err := http.NewRequest("GET", path, nil) // No need for bytes.NewBuffer(nil) for GET requests without a body
	if err != nil {
		return model2.AuthentikUser{}, err
	}
	req.Header.Set("Authorization", bearer)
	req.Header.Add("Accept", "application/json")

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Always follow redirects
			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error on request:", err)
		return model2.AuthentikUser{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Println("HTTP error:", resp.Status)
		return model2.AuthentikUser{}, fmt.Errorf("HTTP error: %s", resp.Status)
	}

	var user model2.AuthentikUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		log.Println("Error decoding response:", err)
		return model2.AuthentikUser{}, err
	}

	return user, nil
}
func NewAuthentikService(db *gorm.DB) AuthentikService {
	return &authentikService{
		db: db,
	}
}
