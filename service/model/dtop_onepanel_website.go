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
	Type           string `json:"type"`
	Alias          string `json:"alias"`
	Remark         string `json:"remark"`
	AppType        string `json:"appType"`
	WebSiteGroupID int    `json:"webSiteGroupId"`
	OtherDomains   string `json:"otherDomains"`
	Proxy          string `json:"proxy"`
	Appinstall     struct {
		AppID       int    `json:"appId"`
		Name        string `json:"name"`
		AppDetailID int    `json:"appDetailId"`
		Params      struct {
		} `json:"params"`
		Version       string `json:"version"`
		Appkey        string `json:"appkey"`
		Advanced      bool   `json:"advanced"`
		CPUQuota      int    `json:"cpuQuota"`
		MemoryLimit   int    `json:"memoryLimit"`
		MemoryUnit    string `json:"memoryUnit"`
		ContainerName string `json:"containerName"`
		AllowPort     bool   `json:"allowPort"`
	} `json:"appinstall"`
	IPV6          bool   `json:"IPV6"`
	EnableFtp     bool   `json:"enableFtp"`
	FtpUser       string `json:"ftpUser"`
	FtpPassword   string `json:"ftpPassword"`
	ProxyType     string `json:"proxyType"`
	Port          int    `json:"port"`
	ProxyProtocol string `json:"proxyProtocol"`
	ProxyAddress  string `json:"proxyAddress"`
	RuntimeType   string `json:"runtimeType"`
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
