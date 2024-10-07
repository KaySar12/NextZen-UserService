package model

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

