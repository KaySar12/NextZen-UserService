package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/IceWhaleTech/CasaOS-UserService/pkg/config"
	"github.com/IceWhaleTech/CasaOS-UserService/service/model"
)

type OMVService interface {
	LoginSession(userName string, password string) (string, []*http.Cookie)
	Logout(sessionID string) (string, error)
	GetUser(username string, sessionID string) (string, error)
	AuthUser(username string, password string, sessionID string) (string, error)
	SetUser(m model.UserDBModel) model.UserDBModel
	ApplyChange()
}
type omvService struct {
}

// AuthUser implements OMVService.

func (o *omvService) LoginSession(username string, password string) (string, []*http.Cookie) {
	postBody, _ := json.Marshal(map[string]interface{}{
		"service": "session",
		"method":  "login",
		"params": map[string]string{
			"username": username,
			"password": password,
		},
	})
	responseBody := bytes.NewBuffer(postBody)
	response, err := http.Post(config.AppInfo.OMVServer, "application/json", responseBody)
	cookies := response.Cookies()
	if err != nil {
		fmt.Print(err.Error())
		os.Exit(1)
	}
	responseData, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	return string(responseData), cookies
}
func (o *omvService) Logout(sessionID string) (string, error) {
	postBody, _ := json.Marshal(map[string]interface{}{
		"service": "UserMgmt",
		"method":  "logout",
		"params":  nil,
	})
	responseBody := bytes.NewBuffer(postBody)
	req, err := http.NewRequest("POST", config.AppInfo.OMVServer, responseBody)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("X-OPENMEDIAVAULT-SESSIONID", sessionID) // Set session ID header
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close() // Ensure the response body is closed
	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP error: %s", resp.Status)
	}

	// Read the response body
	responseData, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %v", err)
	}

	return string(responseData), nil
}
func (o *omvService) AuthUser(username string, password string, sessionID string) (string, error) {
	postBody, _ := json.Marshal(map[string]interface{}{
		"service": "session",
		"method":  "login",
		"params": map[string]string{
			"username": username,
			"password": password,
		},
	})
	responseBody := bytes.NewBuffer(postBody)
	req, err := http.NewRequest("POST", config.AppInfo.OMVServer, responseBody)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("X-OPENMEDIAVAULT-SESSIONID", sessionID) // Set session ID header
	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()
	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP error: %s", resp.Status)
	}
	// Read the response body
	responseData, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %v", err)
	}

	return string(responseData), nil
}
func (o *omvService) GetUser(username string, sessionID string) (string, error) {
	// Prepare the RPC request
	postBody, _ := json.Marshal(map[string]interface{}{
		"service": "UserMgmt",
		"method":  "getUser",
		"params": map[string]string{
			"name": username,
		},
	})
	responseBody := bytes.NewBuffer(postBody)

	// Create HTTP request and set session ID header
	req, err := http.NewRequest("POST", config.AppInfo.OMVServer, responseBody)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("X-OPENMEDIAVAULT-SESSIONID", sessionID) // Set session ID header

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close() // Ensure the response body is closed

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP error: %s", resp.Status)
	}

	// Read the response body
	responseData, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %v", err)
	}

	return string(responseData), nil
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
