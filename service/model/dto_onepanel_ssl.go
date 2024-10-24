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
type CreateSelfSignedCertRequest struct {
	Name             string `json:"name"`
	KeyType          string `json:"keyType"`
	CommonName       string `json:"commonName"`
	Country          string `json:"country"`
	Organization     string `json:"organization"`
	OrganizationUint string `json:"organizationUint"`
	Province         string `json:"province"`
	City             string `json:"city"`
}
type CreateSelfSignedCertResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		CommonName       string `json:"commonName"`
		Country          string `json:"country"`
		Organization     string `json:"organization"`
		OrganizationUint string `json:"organizationUint"`
		Name             string `json:"name"`
		KeyType          string `json:"keyType"`
		Province         string `json:"province"`
		City             string `json:"city"`
	} `json:"data"`
}
type SelfSignedIssueRequest struct {
	KeyType     string `json:"keyType"`
	Domains     string `json:"domains"`
	ID          int    `json:"id"`
	Time        int    `json:"time"`
	Unit        string `json:"unit"`
	PushDir     bool   `json:"pushDir"`
	Dir         string `json:"dir"`
	AutoRenew   bool   `json:"autoRenew"`
	Description string `json:"description"`
	ExecShell   bool   `json:"execShell"`
	Shell       string `json:"shell"`
}
type AcmeSearchRequest struct {
	Page     int `json:"page"`
	PageSize int `json:"pageSize"`
}
type SelfSignedCertSearchRequest struct {
	Page     int `json:"page"`
	PageSize int `json:"pageSize"`
}
type SearchSSLRequest struct {
	AcmeAccountID string `json:"acmeAccountID"`
	Page          int    `json:"page"`
	PageSize      int    `json:"pageSize"`
}
type SearchSSLResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Total int `json:"total"`
		Items []struct {
			ID            int             `json:"id"`
			CreatedAt     time.Time       `json:"createdAt"`
			UpdatedAt     time.Time       `json:"updatedAt"`
			PrimaryDomain string          `json:"primaryDomain"`
			PrivateKey    string          `json:"privateKey"`
			Pem           string          `json:"pem"`
			Domains       string          `json:"domains"`
			CertURL       string          `json:"certURL"`
			Type          string          `json:"type"`
			Provider      string          `json:"provider"`
			Organization  string          `json:"organization"`
			DNSAccountID  int             `json:"dnsAccountId"`
			AcmeAccountID int             `json:"acmeAccountId"`
			CaID          int             `json:"caId"`
			AutoRenew     bool            `json:"autoRenew"`
			ExpireDate    time.Time       `json:"expireDate"`
			StartDate     time.Time       `json:"startDate"`
			Status        string          `json:"status"`
			Message       string          `json:"message"`
			KeyType       string          `json:"keyType"`
			PushDir       bool            `json:"pushDir"`
			Dir           string          `json:"dir"`
			Description   string          `json:"description"`
			SkipDNS       bool            `json:"skipDNS"`
			Nameserver1   string          `json:"nameserver1"`
			Nameserver2   string          `json:"nameserver2"`
			DisableCNAME  bool            `json:"disableCNAME"`
			ExecShell     bool            `json:"execShell"`
			Shell         string          `json:"shell"`
			AcmeAccount   AcmeAccount     `json:"acmeAccount"`
			DNSAccount    DNSAccount      `json:"dnsAccount"`
			Websites      []WebsiteDetail `json:"websites"`
			LogPath       string          `json:"logPath"`
		} `json:"items"`
	} `json:"data"`
}
type WebsiteHttpsConfigRequest struct {
	AcmeAccountID   int      `json:"acmeAccountID"`
	Enable          bool     `json:"enable"`
	WebsiteID       int      `json:"websiteId"`
	WebsiteSSLID    int      `json:"websiteSSLId"`
	Type            string   `json:"type"`
	ImportType      string   `json:"importType"`
	PrivateKey      string   `json:"privateKey"`
	Certificate     string   `json:"certificate"`
	PrivateKeyPath  string   `json:"privateKeyPath"`
	CertificatePath string   `json:"certificatePath"`
	HTTPConfig      string   `json:"httpConfig"`
	Hsts            bool     `json:"hsts"`
	Algorithm       string   `json:"algorithm"`
	SSLProtocol     []string `json:"SSLProtocol"`
}
type AcmeSearchResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Total int           `json:"total"`
		Items []AcmeAccount `json:"items"`
	} `json:"data"`
}
type SelfSignedCertSearchResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Total int `json:"total"`
		Items []struct {
			ID               int       `json:"id"`
			CreatedAt        time.Time `json:"createdAt"`
			UpdatedAt        time.Time `json:"updatedAt"`
			Csr              string    `json:"csr"`
			Name             string    `json:"name"`
			PrivateKey       string    `json:"privateKey"`
			KeyType          string    `json:"keyType"`
			CommonName       string    `json:"commonName"`
			Country          string    `json:"country"`
			Organization     string    `json:"organization"`
			OrganizationUint string    `json:"organizationUint"`
			Province         string    `json:"province"`
			City             string    `json:"city"`
		} `json:"items"`
	} `json:"data"`
}

type WebsiteDetail struct {
	ID             int         `json:"id"`
	CreatedAt      time.Time   `json:"createdAt"`
	UpdatedAt      time.Time   `json:"updatedAt"`
	Protocol       string      `json:"protocol"`
	PrimaryDomain  string      `json:"primaryDomain"`
	Type           string      `json:"type"`
	Alias          string      `json:"alias"`
	Remark         string      `json:"remark"`
	Status         string      `json:"status"`
	HTTPConfig     string      `json:"httpConfig"`
	ExpireDate     time.Time   `json:"expireDate"`
	Proxy          string      `json:"proxy"`
	ProxyType      string      `json:"proxyType"`
	SiteDir        string      `json:"siteDir"`
	ErrorLog       bool        `json:"errorLog"`
	AccessLog      bool        `json:"accessLog"`
	DefaultServer  bool        `json:"defaultServer"`
	IPV6           bool        `json:"IPV6"`
	Rewrite        string      `json:"rewrite"`
	WebSiteGroupID int         `json:"webSiteGroupId"`
	WebSiteSSLID   int         `json:"webSiteSSLId"`
	RuntimeID      int         `json:"runtimeID"`
	AppInstallID   int         `json:"appInstallId"`
	FtpID          int         `json:"ftpId"`
	User           string      `json:"user"`
	Group          string      `json:"group"`
	Domains        interface{} `json:"domains"`
	WebSiteSSL     WebsiteSSL  `json:"webSiteSSL"`
}
type WebsiteSSL struct {
	ID            int         `json:"id"`
	CreatedAt     time.Time   `json:"createdAt"`
	UpdatedAt     time.Time   `json:"updatedAt"`
	PrimaryDomain string      `json:"primaryDomain"`
	PrivateKey    string      `json:"privateKey"`
	Pem           string      `json:"pem"`
	Domains       string      `json:"domains"`
	CertURL       string      `json:"certURL"`
	Type          string      `json:"type"`
	Provider      string      `json:"provider"`
	Organization  string      `json:"organization"`
	DNSAccountID  int         `json:"dnsAccountId"`
	AcmeAccountID int         `json:"acmeAccountId"`
	CaID          int         `json:"caId"`
	AutoRenew     bool        `json:"autoRenew"`
	ExpireDate    time.Time   `json:"expireDate"`
	StartDate     time.Time   `json:"startDate"`
	Status        string      `json:"status"`
	Message       string      `json:"message"`
	KeyType       string      `json:"keyType"`
	PushDir       bool        `json:"pushDir"`
	Dir           string      `json:"dir"`
	Description   string      `json:"description"`
	SkipDNS       bool        `json:"skipDNS"`
	Nameserver1   string      `json:"nameserver1"`
	Nameserver2   string      `json:"nameserver2"`
	DisableCNAME  bool        `json:"disableCNAME"`
	ExecShell     bool        `json:"execShell"`
	Shell         string      `json:"shell"`
	AcmeAccount   AcmeAccount `json:"acmeAccount"`
	DNSAccount    DNSAccount  `json:"dnsAccount"`
	Websites      interface{} `json:"websites"`
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
