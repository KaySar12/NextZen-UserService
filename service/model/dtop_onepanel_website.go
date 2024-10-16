package model

import "time"

type SearchWebsiteRequest struct {
	Name           string `json:"name"`
	Page           int    `json:"page"`
	PageSize       int    `json:"pageSize"`
	OrderBy        string `json:"orderBy"`
	Order          string `json:"order"`
	WebsiteGroupID int    `json:"websiteGroupId"`
}

type SearchWebsiteResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Total int `json:"total"`
		Items []struct {
			ID            int       `json:"id"`
			CreatedAt     time.Time `json:"createdAt"`
			Protocol      string    `json:"protocol"`
			PrimaryDomain string    `json:"primaryDomain"`
			Type          string    `json:"type"`
			Alias         string    `json:"alias"`
			Remark        string    `json:"remark"`
			Status        string    `json:"status"`
			ExpireDate    time.Time `json:"expireDate"`
			SitePath      string    `json:"sitePath"`
			AppName       string    `json:"appName"`
			RuntimeName   string    `json:"runtimeName"`
			SslExpireDate time.Time `json:"sslExpireDate"`
			SslStatus     string    `json:"sslStatus"`
			AppInstallID  int       `json:"appInstallId"`
			RuntimeType   string    `json:"runtimeType"`
		} `json:"items"`
	} `json:"data"`
}

type CreateWebsiteRequest struct {
	PrimaryDomain  string `json:"primaryDomain"`
	Type           string `json:"type,omitempty"`
	Alias          string `json:"alias,omitempty"`
	Remark         string `json:"remark,omitempty"`
	AppType        string `json:"appType,omitempty"`
	WebSiteGroupID int64  `json:"webSiteGroupId,omitempty"`
	OtherDomains   string `json:"otherDomains,omitempty"`
	Proxy          string `json:"proxy,omitempty"`
	Appinstall     struct {
		AppID         int64    `json:"appId,omitempty"`
		Name          string   `json:"name,omitempty"`
		AppDetailID   int64    `json:"appDetailId,omitempty"`
		Params        struct{} `json:"params,omitempty"`
		Version       string   `json:"version,omitempty"`
		Appkey        string   `json:"appkey,omitempty"`
		Advanced      bool     `json:"advanced,omitempty"`
		CPUQuota      int64    `json:"cpuQuota,omitempty"`
		MemoryLimit   int64    `json:"memoryLimit,omitempty"`
		MemoryUnit    string   `json:"memoryUnit,omitempty"`
		ContainerName string   `json:"containerName,omitempty"`
		AllowPort     bool     `json:"allowPort,omitempty"`
	} `json:"appinstall,omitempty"`
	IPV6          bool   `json:"IPV6,omitempty"`
	EnableFtp     bool   `json:"enableFtp,omitempty"`
	FtpUser       string `json:"ftpUser,omitempty"`
	FtpPassword   string `json:"ftpPassword,omitempty"`
	ProxyType     string `json:"proxyType,omitempty"`
	Port          int64  `json:"port,omitempty"`
	ProxyProtocol string `json:"proxyProtocol,omitempty"`
	ProxyAddress  string `json:"proxyAddress,omitempty"`
	RuntimeType   string `json:"runtimeType,omitempty"`
}

type DeleteWebsiteRequest struct {
	ID           int  `json:"id"`
	DeleteApp    bool `json:"deleteApp"`
	DeleteBackup bool `json:"deleteBackup"`
	ForceDelete  bool `json:"forceDelete"`
}

type GenericResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
	} `json:"data"`
}

type ProxyWebsiteRequest struct {
	ID int `json:"id"`
}

type ProxyWebsiteResponse struct {
	Code    int           `json:"code"`
	Message string        `json:"message"`
	Data    []ProxyDetail `json:"data"`
}

type ProxyDetail struct {
	ID        int    `json:"id"`
	Operate   string `json:"operate"`
	Enable    bool   `json:"enable"`
	Cache     bool   `json:"cache"`
	CacheTime int    `json:"cacheTime"`
	CacheUnit string `json:"cacheUnit"`
	Name      string `json:"name"`
	Modifier  string `json:"modifier"`
	Match     string `json:"match"`
	ProxyPass string `json:"proxyPass"`
	ProxyHost string `json:"proxyHost"`
	Content   string `json:"content"`
	FilePath  string `json:"filePath"`
	Replaces  struct {
	} `json:"replaces"`
	Sni           bool   `json:"sni"`
	ProxyProtocol string `json:"proxyProtocol"`
	ProxyAddress  string `json:"proxyAddress"`
}
type WebsiteHttpsRequest struct {
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

type WebsiteHttpsResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Enable     bool   `json:"enable"`
		HTTPConfig string `json:"httpConfig"`
		SSL        struct {
			ID            int       `json:"id"`
			CreatedAt     time.Time `json:"createdAt"`
			UpdatedAt     time.Time `json:"updatedAt"`
			PrimaryDomain string    `json:"primaryDomain"`
			PrivateKey    string    `json:"privateKey"`
			Pem           string    `json:"pem"`
			Domains       string    `json:"domains"`
			CertURL       string    `json:"certURL"`
			Type          string    `json:"type"`
			Provider      string    `json:"provider"`
			Organization  string    `json:"organization"`
			DNSAccountID  int       `json:"dnsAccountId"`
			AcmeAccountID int       `json:"acmeAccountId"`
			CaID          int       `json:"caId"`
			AutoRenew     bool      `json:"autoRenew"`
			ExpireDate    time.Time `json:"expireDate"`
			StartDate     time.Time `json:"startDate"`
			Status        string    `json:"status"`
			Message       string    `json:"message"`
			KeyType       string    `json:"keyType"`
			PushDir       bool      `json:"pushDir"`
			Dir           string    `json:"dir"`
			Description   string    `json:"description"`
			SkipDNS       bool      `json:"skipDNS"`
			Nameserver1   string    `json:"nameserver1"`
			Nameserver2   string    `json:"nameserver2"`
			DisableCNAME  bool      `json:"disableCNAME"`
			ExecShell     bool      `json:"execShell"`
			Shell         string    `json:"shell"`
			AcmeAccount   struct {
				ID         int       `json:"id"`
				CreatedAt  time.Time `json:"createdAt"`
				UpdatedAt  time.Time `json:"updatedAt"`
				Email      string    `json:"email"`
				URL        string    `json:"url"`
				Type       string    `json:"type"`
				EabKid     string    `json:"eabKid"`
				EabHmacKey string    `json:"eabHmacKey"`
				KeyType    string    `json:"keyType"`
			} `json:"acmeAccount"`
			DNSAccount struct {
				ID        int       `json:"id"`
				CreatedAt time.Time `json:"createdAt"`
				UpdatedAt time.Time `json:"updatedAt"`
				Name      string    `json:"name"`
				Type      string    `json:"type"`
			} `json:"dnsAccount"`
			Websites interface{} `json:"websites"`
		} `json:"SSL"`
		SSLProtocol []string `json:"SSLProtocol"`
		Algorithm   string   `json:"algorithm"`
		Hsts        bool     `json:"hsts"`
	} `json:"data"`
}
