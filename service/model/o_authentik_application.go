package model

type AuthentikApplication struct {
	Pagination struct {
		Count      int64 `json:"count"`
		Current    int64 `json:"current"`
		EndIndex   int64 `json:"end_index"`
		Next       int64 `json:"next"`
		Previous   int64 `json:"previous"`
		StartIndex int64 `json:"start_index"`
		TotalPages int64 `json:"total_pages"`
	} `json:"pagination"`
	Results []struct {
		BackchannelProviders    []interface{} `json:"backchannel_providers"`
		BackchannelProvidersObj []interface{} `json:"backchannel_providers_obj"`
		Group                   string        `json:"group"`
		LaunchURL               string        `json:"launch_url"`
		MetaDescription         string        `json:"meta_description"`
		MetaIcon                string        `json:"meta_icon"`
		MetaLaunchURL           string        `json:"meta_launch_url"`
		MetaPublisher           string        `json:"meta_publisher"`
		Name                    string        `json:"name"`
		OpenInNewTab            bool          `json:"open_in_new_tab"`
		Pk                      string        `json:"pk"`
		PolicyEngineMode        string        `json:"policy_engine_mode"`
		Provider                int64         `json:"provider"`
		ProviderObj             struct {
			AssignedApplicationName string   `json:"assigned_application_name"`
			AssignedApplicationSlug string   `json:"assigned_application_slug"`
			AuthenticationFlow      string   `json:"authentication_flow"`
			AuthorizationFlow       string   `json:"authorization_flow"`
			Component               string   `json:"component"`
			MetaModelName           string   `json:"meta_model_name"`
			Name                    string   `json:"name"`
			Pk                      int64    `json:"pk"`
			PropertyMappings        []string `json:"property_mappings"`
			VerboseName             string   `json:"verbose_name"`
			VerboseNamePlural       string   `json:"verbose_name_plural"`
		} `json:"provider_obj"`
		Slug string `json:"slug"`
	} `json:"results"`
}
