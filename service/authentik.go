package service

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	model2 "github.com/KaySar12/NextZen-UserService/service/model"
	"gorm.io/gorm"
)

type AuthentikService interface {
	GetUserInfo(accessToken string, baseURL string) (model2.AuthentikUser, error)
	GetUserApp(accessToken string, baseURL string) (model2.AuthentikApplication, error)
	CreateSettings(m model2.AuthentikCredentialsDBModel) model2.AuthentikCredentialsDBModel
	UpdateSettings(m model2.AuthentikCredentialsDBModel) (model2.AuthentikCredentialsDBModel, error)
	GetSettings() (model2.AuthentikCredentialsDBModel, error)
	ValidateToken(clientId string, clientSecret string, accessToken string, baseURL string) (model2.AuthentikToken, error)
	HealthCheck(baseURL string) (string, error)
}

type authentikService struct {
	db *gorm.DB
}

var (
	APICorePrefix = "/api/v3/core"
)

func (a *authentikService) CreateSettings(m model2.AuthentikCredentialsDBModel) model2.AuthentikCredentialsDBModel {
	a.db.Create(&m)
	return m
}
func (a *authentikService) UpdateSettings(m model2.AuthentikCredentialsDBModel) (model2.AuthentikCredentialsDBModel, error) {
	// Find the first matching record
	var existing model2.AuthentikCredentialsDBModel
	result := a.db.First(&existing)
	if result.Error != nil {
		return existing, result.Error
	}

	// Update the existing record
	existing.ClientID = m.ClientID
	existing.ClientSecret = m.ClientSecret
	existing.Issuer = m.Issuer
	existing.AuthUrl = m.AuthUrl
	existing.CallbackUrl = m.CallbackUrl

	// Save the updated record
	result = a.db.Save(&existing)
	if result.Error != nil {
		return existing, result.Error
	}

	return existing, nil
}
func (a *authentikService) GetSettings() (model2.AuthentikCredentialsDBModel, error) {
	var m model2.AuthentikCredentialsDBModel
	result := a.db.First(&m)
	if result.Error != nil {
		return model2.AuthentikCredentialsDBModel{}, result.Error
	}
	return m, nil
}
func (a *authentikService) HealthCheck(baseURL string) (string, error) {
	// Check health/live first
	pathLive := baseURL + "/-/health/live/"
	reqLive, err := http.NewRequest("GET", pathLive, nil)
	if err != nil {
		log.Println("Error creating health/live request:", err)
		return "Offline", err
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // Always follow redirects
		},
	}

	respLive, err := client.Do(reqLive)
	if err != nil {
		log.Println("Error on health/live request:", err)
		return "Offline", err // Exit if the request fails
	}
	defer respLive.Body.Close()

	// Check if health/live is 204 before proceeding
	if respLive.StatusCode == http.StatusNoContent {
		// Now check health/ready
		pathReady := baseURL + "/-/health/ready/"
		reqReady, err := http.NewRequest("GET", pathReady, nil)
		if err != nil {
			log.Println("Error creating health/ready request:", err)
			return "Offline", err
		}

		respReady, err := client.Do(reqReady)
		if err != nil {
			log.Println("Error on health/ready request:", err)
			return "Offline", err
		}
		defer respReady.Body.Close()

		if respReady.StatusCode != http.StatusNoContent {
			log.Println("HTTP error on health/ready:", respReady.Status)
			return "Starting", nil
		} else {
			log.Println("Authentik is fully healthy!")
			return "Live", nil
		}

	} else {
		log.Println("HTTP error on health/live:", respLive.Status)
		return "Offline", err
	}
}
func (a *authentikService) ValidateToken(clientId string, clientSecret string, accessToken string, baseURL string) (model2.AuthentikToken, error) {
	auth := clientId + ":" + clientSecret
	basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
	path := baseURL + "/application/o/introspect/"
	formData := url.Values{}
	formData.Set("token", accessToken)
	reqBody := strings.NewReader(formData.Encode())
	req, err := http.NewRequest("POST", path, reqBody)
	if err != nil {
		return model2.AuthentikToken{}, fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("Authorization", basicAuth)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return model2.AuthentikToken{}, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Println("HTTP error:", resp.Status)
		return model2.AuthentikToken{}, fmt.Errorf("HTTP error: %s", resp.Status)
	}
	var token model2.AuthentikToken
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		log.Println("Error decoding response:", err)
		return model2.AuthentikToken{}, err
	}
	return token, nil
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
