package model

import "time"

type CreateSSLRequest struct {
	ID            int    `json:"id"`
	PrimaryDomain string `json:"primaryDomain"`
	OtherDomains  string `json:"otherDomains"`
	Provider      string `json:"provider"`
	WebsiteID     int    `json:"websiteId"`
	AcmeAccountID int    `json:"acmeAccountId"`
	AutoRenew     bool   `json:"autoRenew"`
	KeyType       string `json:"keyType"`
	PushDir       bool   `json:"pushDir"`
	Dir           string `json:"dir"`
	Description   string `json:"description"`
	DisableCNAME  bool   `json:"disableCNAME"`
	SkipDNS       bool   `json:"skipDNS"`
	Nameserver1   string `json:"nameserver1"`
	Nameserver2   string `json:"nameserver2"`
	ExecShell     bool   `json:"execShell"`
	Shell         string `json:"shell"`
}

type CreateSSLResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		PrimaryDomain string `json:"primaryDomain"`
		OtherDomains  string `json:"otherDomains"`
		Provider      string `json:"provider"`
		AcmeAccountID int    `json:"acmeAccountId"`
		DNSAccountID  int    `json:"dnsAccountId"`
		AutoRenew     bool   `json:"autoRenew"`
		KeyType       string `json:"keyType"`
		Apply         bool   `json:"apply"`
		PushDir       bool   `json:"pushDir"`
		Dir           string `json:"dir"`
		ID            int    `json:"id"`
		Description   string `json:"description"`
		DisableCNAME  bool   `json:"disableCNAME"`
		SkipDNS       bool   `json:"skipDNS"`
		Nameserver1   string `json:"nameserver1"`
		Nameserver2   string `json:"nameserver2"`
		ExecShell     bool   `json:"execShell"`
		Shell         string `json:"shell"`
	} `json:"data"`
}

type AcmeSearchRequest struct {
	Page     int `json:"page"`
	PageSize int `json:"pageSize"`
}

type SearchSSLRequest struct {
	Page     int `json:"page"`
	PageSize int `json:"pageSize"`
}
type SearchSSLResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Total int `json:"total"`
		Items []struct {
			ID            int           `json:"id"`
			CreatedAt     time.Time     `json:"createdAt"`
			UpdatedAt     time.Time     `json:"updatedAt"`
			PrimaryDomain string        `json:"primaryDomain"`
			PrivateKey    string        `json:"privateKey"`
			Pem           string        `json:"pem"`
			Domains       string        `json:"domains"`
			CertURL       string        `json:"certURL"`
			Type          string        `json:"type"`
			Provider      string        `json:"provider"`
			Organization  string        `json:"organization"`
			DNSAccountID  int           `json:"dnsAccountId"`
			AcmeAccountID int           `json:"acmeAccountId"`
			CaID          int           `json:"caId"`
			AutoRenew     bool          `json:"autoRenew"`
			ExpireDate    time.Time     `json:"expireDate"`
			StartDate     time.Time     `json:"startDate"`
			Status        string        `json:"status"`
			Message       string        `json:"message"`
			KeyType       string        `json:"keyType"`
			PushDir       bool          `json:"pushDir"`
			Dir           string        `json:"dir"`
			Description   string        `json:"description"`
			SkipDNS       bool          `json:"skipDNS"`
			Nameserver1   string        `json:"nameserver1"`
			Nameserver2   string        `json:"nameserver2"`
			DisableCNAME  bool          `json:"disableCNAME"`
			ExecShell     bool          `json:"execShell"`
			Shell         string        `json:"shell"`
			AcmeAccount   AcmeAccount   `json:"acmeAccount"`
			DNSAccount    DNSAccount    `json:"dnsAccount"`
			Websites      []interface{} `json:"websites"`
			LogPath       string        `json:"logPath"`
		} `json:"items"`
	} `json:"data"`
}
type AcmeSearchResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Total int           `json:"total"`
		Items []AcmeAccount `json:"items"`
	} `json:"data"`
}

type AcmeAccount struct {
	ID         int       `json:"id"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
	Email      string    `json:"email"`
	URL        string    `json:"url"`
	Type       string    `json:"type"`
	EabKid     string    `json:"eabKid"`
	EabHmacKey string    `json:"eabHmacKey"`
	KeyType    string    `json:"keyType"`
}
type DNSAccount struct {
	ID        int       `json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
}
