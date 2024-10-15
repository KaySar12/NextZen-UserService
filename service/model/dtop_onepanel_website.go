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
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    []struct {
		ID        int         `json:"id"`
		Operate   string      `json:"operate"`
		Enable    bool        `json:"enable"`
		Cache     bool        `json:"cache"`
		CacheTime int         `json:"cacheTime"`
		CacheUnit string      `json:"cacheUnit"`
		Name      string      `json:"name"`
		Modifier  string      `json:"modifier"`
		Match     string      `json:"match"`
		ProxyPass string      `json:"proxyPass"`
		ProxyHost string      `json:"proxyHost"`
		Content   string      `json:"content"`
		FilePath  string      `json:"filePath"`
		Replaces  interface{} `json:"replaces"`
		Sni       bool        `json:"sni"`
	} `json:"data"`
}

type UpdateProxyRequest struct {
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
