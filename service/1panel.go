package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	model2 "github.com/KaySar12/NextZen-UserService/service/model"
)

type OnePanelService interface {
	Login(m model2.OnePanelCredentials, baseURL string) (model2.LoginResponse, []*http.Cookie, error)
	Logout(m model2.OnePanelCredentials, baseURL string) (model2.LogoutResponse, error)
	HealthCheck(baseURL string) (string, error)
	SearchInstalledApp(p model2.InstalledAppRequest, baseURL string) (model2.InstalledAppResponse, error)
	// InstallApp()
	SearchWebsite(m model2.SearchWebsiteRequest, baseUrl string, headers map[string]string) (model2.SearchWebsiteResponse, error)
	CreateWebsite(m model2.CreateWebsiteRequest, baseUrl string, headers map[string]string) (model2.GenericResponse, error)
	DeleteWebsite(m model2.DeleteWebsiteRequest, baseUrl string, headers map[string]string) (model2.GenericResponse, error)
	GetProxyWebsite(m model2.ProxyWebsiteRequest, baseUrl string, headers map[string]string) (model2.ProxyWebsiteResponse, error)
	UpdateProxyWebsite(m model2.UpdateProxyRequest, baseUrl string, headers map[string]string) (model2.GenericResponse, error)
}

var (
	prefixV1 = "/api/v1"
)

type onePanelService struct {
}

// TODO A lot of redundant code need refactor
func (o *onePanelService) UpdateProxyWebsite(m model2.UpdateProxyRequest, baseUrl string, headers map[string]string) (model2.GenericResponse, error) {
	path := baseUrl + "/api/v1/websites/proxies/update"
	reqBody, err := json.Marshal(m)
	if err != nil {
		return model2.GenericResponse{}, fmt.Errorf("error marshaling request body: %v", err)
	}
	req, err := http.NewRequest("POST", path, bytes.NewReader(reqBody))
	if err != nil {
		return model2.GenericResponse{}, fmt.Errorf("error creating request: %v", err)
	}
	// Add headers to the request
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return model2.GenericResponse{}, fmt.Errorf("error making request: %v", err)
	}

	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return model2.GenericResponse{}, fmt.Errorf("HTTP error: %s", resp.Status)
	}
	var result model2.GenericResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return model2.GenericResponse{}, fmt.Errorf("error decoding response: %v", err)
	}
	return result, nil
}

func (o *onePanelService) GetProxyWebsite(m model2.ProxyWebsiteRequest, baseUrl string, headers map[string]string) (model2.ProxyWebsiteResponse, error) {
	path := baseUrl + "/api/v1/websites/proxies"
	reqBody, err := json.Marshal(m)
	if err != nil {
		return model2.ProxyWebsiteResponse{}, fmt.Errorf("error marshaling request body: %v", err)
	}
	req, err := http.NewRequest("POST", path, bytes.NewReader(reqBody))
	if err != nil {
		return model2.ProxyWebsiteResponse{}, fmt.Errorf("error creating request: %v", err)
	}
	// Add headers to the request
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return model2.ProxyWebsiteResponse{}, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return model2.ProxyWebsiteResponse{}, fmt.Errorf("HTTP error: %s", resp.Status)
	}
	var result model2.ProxyWebsiteResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return model2.ProxyWebsiteResponse{}, fmt.Errorf("error decoding response: %v", err)
	}
	return result, nil
}
func (o *onePanelService) SearchWebsite(m model2.SearchWebsiteRequest, baseUrl string, headers map[string]string) (model2.SearchWebsiteResponse, error) {
	path := baseUrl + "/api/v1/websites/search"
	reqBody, err := json.Marshal(m)
	if err != nil {
		return model2.SearchWebsiteResponse{}, fmt.Errorf("error marshaling request body: %v", err)
	}
	req, err := http.NewRequest("POST", path, bytes.NewReader(reqBody))
	if err != nil {
		return model2.SearchWebsiteResponse{}, fmt.Errorf("error creating request: %v", err)
	}
	// Add headers to the request
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return model2.SearchWebsiteResponse{}, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return model2.SearchWebsiteResponse{}, fmt.Errorf("HTTP error: %s", resp.Status)
	}
	var result model2.SearchWebsiteResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return model2.SearchWebsiteResponse{}, fmt.Errorf("error decoding response: %v", err)
	}
	return result, nil
}
func (o *onePanelService) CreateWebsite(m model2.CreateWebsiteRequest, baseUrl string, headers map[string]string) (model2.GenericResponse, error) {
	path := baseUrl + "/api/v1/websites"
	reqBody, err := json.Marshal(m)
	if err != nil {
		return model2.GenericResponse{}, fmt.Errorf("error marshaling request body: %v", err)
	}
	req, err := http.NewRequest("POST", path, bytes.NewReader(reqBody))
	if err != nil {
		return model2.GenericResponse{}, fmt.Errorf("error creating request: %v", err)
	}
	// Add headers to the request
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return model2.GenericResponse{}, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return model2.GenericResponse{}, fmt.Errorf("HTTP error: %s", resp.Status)
	}
	var result model2.GenericResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return model2.GenericResponse{}, fmt.Errorf("error decoding response: %v", err)
	}
	return result, nil
}
func (o *onePanelService) DeleteWebsite(m model2.DeleteWebsiteRequest, baseUrl string, headers map[string]string) (model2.GenericResponse, error) {
	path := baseUrl + "/api/v1/websites/del"
	reqBody, err := json.Marshal(m)
	if err != nil {
		return model2.GenericResponse{}, fmt.Errorf("error marshaling request body: %v", err)
	}
	req, err := http.NewRequest("POST", path, bytes.NewReader(reqBody))
	if err != nil {
		return model2.GenericResponse{}, fmt.Errorf("error creating request: %v", err)
	}
	// Add headers to the request
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return model2.GenericResponse{}, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return model2.GenericResponse{}, fmt.Errorf("HTTP error: %s", resp.Status)
	}
	var result model2.GenericResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return model2.GenericResponse{}, fmt.Errorf("error decoding response: %v", err)
	}
	return result, nil
}
func (o *onePanelService) SearchInstalledApp(m model2.InstalledAppRequest, baseUrl string) (model2.InstalledAppResponse, error) {
	path := baseUrl + "/api/v1/websites/search"
	reqBody, err := json.Marshal(m)
	if err != nil {
		return model2.InstalledAppResponse{}, fmt.Errorf("error marshaling request body: %v", err)
	}
	req, err := http.NewRequest("POST", path, bytes.NewReader(reqBody))
	// req.AddCookie()
	if err != nil {
		return model2.InstalledAppResponse{}, fmt.Errorf("error creating request: %v", err)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return model2.InstalledAppResponse{}, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return model2.InstalledAppResponse{}, fmt.Errorf("HTTP error: %s", resp.Status)
	}
	var result model2.InstalledAppResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return model2.InstalledAppResponse{}, fmt.Errorf("error decoding response: %v", err)
	}

	return result, nil
}
func (o *onePanelService) Login(m model2.OnePanelCredentials, baseURL string) (model2.LoginResponse, []*http.Cookie, error) {
	path := baseURL + prefixV1 + "/auth/login"

	// Create the request body by marshaling the credentials into JSON
	reqBody, err := json.Marshal(m)
	if err != nil {
		return model2.LoginResponse{}, []*http.Cookie{}, fmt.Errorf("error marshaling request body: %v", err)
	}

	req, err := http.NewRequest("POST", path, bytes.NewReader(reqBody))
	if err != nil {
		return model2.LoginResponse{}, []*http.Cookie{}, fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Reuse the HTTP client (consider making it a field in onePanelService)
	client := &http.Client{}
	resp, err := client.Do(req)
	cookies := resp.Cookies()
	if err != nil {
		return model2.LoginResponse{}, []*http.Cookie{}, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return model2.LoginResponse{}, []*http.Cookie{}, fmt.Errorf("HTTP error: %s", resp.Status)
	}

	var result model2.LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return model2.LoginResponse{}, []*http.Cookie{}, fmt.Errorf("error decoding response: %v", err)
	}

	return result, cookies, nil
}

func (o *onePanelService) Logout(m model2.OnePanelCredentials, baseURL string) (model2.LogoutResponse, error) {
	return model2.LogoutResponse{}, nil
}

func (o *onePanelService) HealthCheck(baseURL string) (string, error) {
	path := baseURL + "/health"
	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		log.Println("Error creating health/live request:", err)
		return "Offline", err
	}
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // Always follow redirects
		},
	}
	respLive, err := client.Do(req)
	if err != nil {
		log.Println("Error on health/live request:", err)
		return "Offline", err // Exit if the request fails
	}
	defer respLive.Body.Close()
	if respLive.StatusCode == http.StatusOK {
		return "Live", nil
	}
	return "Offline", err
}

func NewOnePanelService() OnePanelService {
	return &onePanelService{}
}
