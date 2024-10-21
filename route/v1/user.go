package v1

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	json2 "encoding/json"
	"fmt"
	"image"
	"image/png"
	"io"
	"log"
	"net/http"
	"net/url"
	url2 "net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/KaySar12/NextZen-Common/external"
	"github.com/KaySar12/NextZen-Common/utils/common_err"
	"github.com/KaySar12/NextZen-Common/utils/jwt"
	"github.com/KaySar12/NextZen-Common/utils/logger"
	"github.com/KaySar12/NextZen-UserService/common"
	"github.com/KaySar12/NextZen-UserService/model"
	"github.com/KaySar12/NextZen-UserService/model/system_model"
	"github.com/KaySar12/NextZen-UserService/pkg/config"
	"github.com/KaySar12/NextZen-UserService/pkg/utils/encryption"
	"github.com/KaySar12/NextZen-UserService/pkg/utils/file"
	"github.com/KaySar12/NextZen-UserService/service"
	model2 "github.com/KaySar12/NextZen-UserService/service/model"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	uuid "github.com/satori/go.uuid"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
)

var (
	authServer          = "http://accessmanager.local"
	clientID            = "6KwKSxLCtaQ4r6HoAn3gdNMbNOAf75j3SejLIAx7"
	clientSecret        = "PE05fcDP4qESUmyZ1TNYpZNBxRPq70VpFI81vehsoJ6WhGz5yPXMljrFrOdMRdRhrYmF03fHWTZHgO9ZdNENrLN13BzL8CAgtEkTsyjXfgx9GvISheIjYfpSfvo219fL"
	authURL             = "http://accessmanager.local/application/o/nextzenos-oidc/"
	callbackURL         = "http://nextzenos.local/v1/users/oidc/callback"
	onePanelServer      = "http://nextweb.local"
	onePanelName        = "nextzen"
	onePanelPassword    = "Smartyourlife123@*"
	authentik_api_token = "jidFioAIXpgl8awyk2O17K8W7vZzlXhOO0QXGxEhMDJdn9g747EQjmaI0i3e"
)

type OIDCSetting struct {
	Settings struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		Issuer       string `json:"issuer"`
		AuthURL      string `json:"authUrl"`
		CallbackURL  string `json:"callbackUrl"`
	} `json:"settings"`
}

// @Summary register user
// @Router /user/register/ [post]
func PostUserRegister(c *gin.Context) {
	json := make(map[string]string)
	c.ShouldBind(&json)

	username := json["username"]
	pwd := json["password"]
	key := json["key"]
	role := json["role"]
	if _, ok := service.UserRegisterHash[key]; !ok {
		c.JSON(common_err.CLIENT_ERROR,
			model.Result{Success: common_err.KEY_NOT_EXIST, Message: common_err.GetMsg(common_err.KEY_NOT_EXIST)})
		return
	}

	if len(username) == 0 || len(pwd) == 0 {
		c.JSON(common_err.CLIENT_ERROR,
			model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
		return
	}
	if len(pwd) < 6 {
		c.JSON(common_err.CLIENT_ERROR,
			model.Result{Success: common_err.PWD_IS_TOO_SIMPLE, Message: common_err.GetMsg(common_err.PWD_IS_TOO_SIMPLE)})
		return
	}
	oldUser := service.MyService.User().GetUserInfoByUserName(username)
	if oldUser.Id > 0 {
		c.JSON(common_err.CLIENT_ERROR,
			model.Result{Success: common_err.USER_EXIST, Message: common_err.GetMsg(common_err.USER_EXIST)})
		return
	}

	user := model2.UserDBModel{}
	user.Username = username
	user.Password = encryption.GetMD5ByStr(pwd)
	user.Role = role
	user = service.MyService.User().CreateUser(user)
	if user.Id == 0 {
		c.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
		return
	}
	file.MkDir(config.AppInfo.UserDataPath + "/" + strconv.Itoa(user.Id))
	delete(service.UserRegisterHash, key)
	c.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS)})
}

var limiter = rate.NewLimiter(rate.Every(time.Minute), 5)

// TODO Cant call login every request(using for testing only)
func ExternalAPIMiddleware(c *gin.Context) {
	session := sessions.Default(c)
	if err := OnePanelLogin(c); err != nil {
		c.JSON(http.StatusUnauthorized, model.Result{
			Success: common_err.SERVICE_ERROR,
			Message: common_err.GetMsg(common_err.SERVICE_ERROR),
		})
		c.Abort()
		return
	}
	sessionId := session.Get("psession")

	if sessionId == nil {
		c.JSON(http.StatusInternalServerError, model.Result{
			Success: common_err.SERVICE_ERROR,
			Message: common_err.GetMsg(common_err.SERVICE_ERROR),
		})
		c.Abort()
		return

	}

	// Add sessionId to the request's Cookie header
	c.Request.Header.Set("Cookie", "psession="+sessionId.(string))
	c.Next()
}
func OnePanelLogin(c *gin.Context) error {
	cred := model2.OnePanelCredentials{
		Name:          onePanelName,
		Password:      onePanelPassword,
		IgnoreCaptcha: true,
		Captcha:       "",
		CaptchaID:     "",
		AuthMethod:    "session",
		Language:      "en",
	}

	response, cookies, err := service.MyService.OnePanel().Login(cred, onePanelServer)
	fmt.Println(response)
	if err != nil {
		logger.Error("OnePanel login failed", zap.Error(err))
		return err
	}

	session := sessions.Default(c)
	for _, cookie := range cookies {
		session.Set(cookie.Name, cookie.Value)
		session.Options(sessions.Options{
			MaxAge: 3600, // 12hrs
		})

	}
	if err := session.Save(); err != nil {
		logger.Error("Failed to save session", zap.Error(err))
		return err
	}
	return nil
}

// func OnePanelLogin(c *gin.Context) {
// 	var cred = model2.OnePanelCredentials{
// 		Name:          onePanelName,
// 		Password:      onePanelPassword,
// 		IgnoreCaptcha: true,
// 		Captcha:       "",
// 		CaptchaID:     "",
// 		AuthMethod:    "session",
// 		Language:      "en",
// 	}

//		response, cookies, err := service.MyService.OnePanel().Login(cred, onePanelServer)
//		if err != nil {
//			c.JSON(common_err.SERVICE_ERROR,
//				model.Result{
//					Success: common_err.SERVICE_ERROR,
//					Message: common_err.GetMsg(common_err.SERVICE_ERROR),
//				})
//		}
//		session := sessions.Default(c)
//		for _, cookie := range cookies {
//			session.Set(cookie.Name, cookie.Value)
//			c.SetCookie(cookie.Name, cookie.Value, 3600, "/", "", false, true)
//		}
//		session.Save()
//		c.JSON(common_err.SUCCESS,
//			model.Result{
//				Success: common_err.SUCCESS,
//				Message: common_err.GetMsg(common_err.SUCCESS),
//				Data:    response,
//			})
//	}
func OnePanelUpdateProxyWebsite(c *gin.Context) {
	json := make(map[string]string)
	c.ShouldBind(&json)
	domain := json["domain"]
	port := json["port"]
	hostname := json["hostname"]
	protocol := json["protocol"]
	var searchParam model2.SearchWebsiteRequest
	searchParam.Name = domain
	searchParam.Page = 1
	searchParam.PageSize = 1
	searchParam.OrderBy = "created_at"
	searchParam.Order = "null"
	searchParam.WebsiteGroupID = 0
	headers := make(map[string]string)
	for key, value := range c.Request.Header {
		headers[key] = value[0]
	}
	var search model2.SearchWebsiteResponse
	search, err := service.MyService.OnePanel().SearchWebsite(searchParam, onePanelServer, headers)
	if err != nil {
		c.JSON(common_err.SERVICE_ERROR,
			model.Result{
				Success: common_err.SERVICE_ERROR,
				Message: common_err.GetMsg(common_err.SERVICE_ERROR),
			})
	}
	if search.Data.Total > 0 {
		var proxy model2.ProxyWebsiteRequest
		proxy.ID = search.Data.Items[0].ID
		var proxyResult model2.ProxyWebsiteResponse
		proxyResult, err := service.MyService.OnePanel().GetProxyWebsite(proxy, onePanelServer, headers)
		if err != nil {
			c.JSON(common_err.SERVICE_ERROR,
				model.Result{
					Success: common_err.SERVICE_ERROR,
					Message: common_err.GetMsg(common_err.SERVICE_ERROR),
				})
		}
		var updateProxy model2.ProxyDetail
		updateProxy = proxyResult.Data[0]
		updateProxy.Operate = "edit"
		updateProxy.ProxyPass = protocol + "://" + hostname + ":" + port
		updateProxyResult, err := service.MyService.OnePanel().UpdateProxyWebsite(updateProxy, onePanelServer, headers)
		if err != nil {
			c.JSON(common_err.SERVICE_ERROR,
				model.Result{
					Success: common_err.SERVICE_ERROR,
					Message: common_err.GetMsg(common_err.SERVICE_ERROR),
				})
		}
		c.JSON(common_err.SUCCESS,
			model.Result{
				Success: common_err.SUCCESS,
				Message: common_err.GetMsg(common_err.SUCCESS),
				Data:    updateProxyResult,
			})
		return
	}
	c.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
		})
}
func OnePanelCreateWebsite(c *gin.Context) {
	json := make(map[string]string)
	c.ShouldBind(&json)
	domain := json["domain"]
	port := json["port"]
	protocol := json["protocol"]
	hostname := json["hostname"]
	var website model2.CreateWebsiteRequest
	website.PrimaryDomain = domain
	website.Type = "proxy"
	website.Alias = domain
	website.AppType = "installed"
	website.WebSiteGroupID = 2
	website.Proxy = protocol + "://" + hostname + ":" + port
	portInt, err := strconv.ParseInt(port, 10, 64)
	if err != nil {
		log.Printf("Error converting port to integer: %v", err)

	}
	website.Port = portInt
	website.ProxyProtocol = protocol
	website.ProxyAddress = hostname + ":" + port
	website.RuntimeType = "php"
	headers := make(map[string]string)
	for key, value := range c.Request.Header {
		headers[key] = value[0]
	}
	var searchParam model2.SearchWebsiteRequest
	searchParam.Name = website.PrimaryDomain
	searchParam.Page = 1
	searchParam.PageSize = 1
	searchParam.OrderBy = "created_at"
	searchParam.Order = "null"
	searchParam.WebsiteGroupID = 0
	search, err := service.MyService.OnePanel().SearchWebsite(searchParam, onePanelServer, headers)
	if err != nil {
		c.JSON(common_err.SERVICE_ERROR,
			model.Result{
				Success: common_err.SERVICE_ERROR,
				Message: common_err.GetMsg(common_err.SERVICE_ERROR),
			})
	}
	if search.Data.Total == 0 {
		if protocol == "https" {
			//TODO Apply Certificate and Enable HTTPS
			var searchSSL model2.SearchSSLRequest
			searchSSL.Page = 1
			searchSSL.PageSize = 50
			ssl, err := service.MyService.OnePanel().SearchWebsiteSSl(searchSSL, onePanelServer, headers)
			if err != nil {
				c.JSON(common_err.SERVICE_ERROR,
					model.Result{
						Success: common_err.SERVICE_ERROR,
						Message: common_err.GetMsg(common_err.SERVICE_ERROR),
					})
			}
			if ssl.Data.Total == 0 {
				createSSL, err := OnePanelApplyWebsiteSSl(domain, search.Data.Items[0].ID, headers)
				if err != nil {
					c.JSON(common_err.SERVICE_ERROR,
						model.Result{
							Success: common_err.SERVICE_ERROR,
							Message: common_err.GetMsg(common_err.SERVICE_ERROR),
						})
				}
				fmt.Println(createSSL)
			}

		}
		response, err := service.MyService.OnePanel().CreateWebsite(website, onePanelServer, headers)
		if err != nil {
			c.JSON(common_err.SERVICE_ERROR,
				model.Result{
					Success: common_err.SERVICE_ERROR,
					Message: common_err.GetMsg(common_err.SERVICE_ERROR),
				})
		}
		c.JSON(common_err.SUCCESS,
			model.Result{
				Success: common_err.SUCCESS,
				Message: common_err.GetMsg(common_err.SUCCESS),
				Data:    response,
			})
		return
	}
	c.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
		})
}

func OnePanelApplyWebsiteSSl(domain string, websiteId int, headers map[string]string) (model2.CreateSSLResponse, error) {
	var searchAcme model2.AcmeSearchRequest
	searchAcme.Page = 1
	searchAcme.PageSize = 50
	acme, err := service.MyService.OnePanel().AcmeAccountSearch(searchAcme, onePanelServer, headers)
	if err != nil {
		return model2.CreateSSLResponse{}, err
	}
	if acme.Data.Total > 0 {
		var createSSL model2.CreateSSLRequest
		createSSL.ID = 1
		createSSL.PrimaryDomain = domain
		createSSL.OtherDomains = ""
		createSSL.Provider = "http"
		createSSL.WebsiteID = websiteId
		createSSL.AcmeAccountID = acme.Data.Items[0].ID
		createSSL.AutoRenew = true
		createSSL.KeyType = "P256"
		createSSL.PushDir = false
		createSSL.Dir = ""
		createSSL.Description = ""
		createSSL.DisableCNAME = false
		createSSL.Nameserver1 = ""
		createSSL.Nameserver2 = ""
		createSSL.ExecShell = false
		createSSL.Shell = ""
		createSSLRes, err := service.MyService.OnePanel().ApplyWebsiteSSl(createSSL, onePanelServer, headers)
		return createSSLRes, err
	}
	return model2.CreateSSLResponse{}, err
}
func OnePanelDeleteWebsite(c *gin.Context) {
	json := make(map[string]string)
	c.ShouldBind(&json)
	domain := json["domain"]
	var searchParam model2.SearchWebsiteRequest
	searchParam.Name = domain
	searchParam.Page = 1
	searchParam.PageSize = 1
	searchParam.OrderBy = "created_at"
	searchParam.Order = "null"
	searchParam.WebsiteGroupID = 0
	headers := make(map[string]string)
	for key, value := range c.Request.Header {
		headers[key] = value[0]
	}
	search, err := service.MyService.OnePanel().SearchWebsite(searchParam, onePanelServer, headers)
	if err != nil {
		c.JSON(common_err.SERVICE_ERROR,
			model.Result{
				Success: common_err.SERVICE_ERROR,
				Message: common_err.GetMsg(common_err.SERVICE_ERROR),
			})
	}
	if search.Data.Total > 0 {
		var delete model2.DeleteWebsiteRequest
		delete.ID = search.Data.Items[0].ID
		delete.DeleteApp = false
		delete.DeleteBackup = false
		delete.ForceDelete = false
		response, err := service.MyService.OnePanel().DeleteWebsite(delete, onePanelServer, headers)
		if err != nil {
			c.JSON(common_err.SERVICE_ERROR,
				model.Result{
					Success: common_err.SERVICE_ERROR,
					Message: common_err.GetMsg(common_err.SERVICE_ERROR),
				})
		}
		c.JSON(common_err.SUCCESS,
			model.Result{
				Success: common_err.SUCCESS,
				Message: common_err.GetMsg(common_err.SUCCESS),
				Data:    response,
			})
		return
	}
	c.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
		})
}
func PostUserLogin(c *gin.Context) {
	if !limiter.Allow() {
		c.JSON(common_err.TOO_MANY_REQUEST,
			model.Result{
				Success: common_err.TOO_MANY_LOGIN_REQUESTS,
				Message: common_err.GetMsg(common_err.TOO_MANY_LOGIN_REQUESTS),
			})
		return
	}

	json := make(map[string]string)
	c.ShouldBind(&json)
	username := json["username"]
	password := json["password"]
	// check params is empty
	if len(username) == 0 || len(password) == 0 {
		c.JSON(common_err.CLIENT_ERROR,
			model.Result{
				Success: common_err.CLIENT_ERROR,
				Message: common_err.GetMsg(common_err.INVALID_PARAMS),
			})
		return
	}
	user := service.MyService.User().GetUserAllInfoByName(username)
	if user.Id == 0 {
		c.JSON(common_err.CLIENT_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST_OR_PWD_INVALID, Message: common_err.GetMsg(common_err.USER_NOT_EXIST_OR_PWD_INVALID)})
		return
	}
	if user.Password != encryption.GetMD5ByStr(password) {
		c.JSON(common_err.CLIENT_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST_OR_PWD_INVALID, Message: common_err.GetMsg(common_err.USER_NOT_EXIST_OR_PWD_INVALID)})
		return
	}
	// clean limit
	limiter = rate.NewLimiter(rate.Every(time.Minute), 5)

	privateKey, _ := service.MyService.User().GetKeyPair()

	token := system_model.VerifyInformation{}

	accessToken, err := jwt.GetAccessToken(username, privateKey, user.Id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: err.Error()})
	}
	token.AccessToken = accessToken

	refreshToken, err := jwt.GetRefreshToken(username, privateKey, user.Id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: err.Error()})
	}
	token.RefreshToken = refreshToken

	token.ExpiresAt = time.Now().Add(3 * time.Hour * time.Duration(1)).Unix()
	data := make(map[string]interface{}, 2)
	user.Password = ""
	data["token"] = token

	// TODO:1 Database fields cannot be external
	data["user"] = user

	c.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data:    data,
		})
}
func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

var oauth2Config oauth2.Config
var oidcInit bool

func InitOIDC() {
	const (
		maxSleep        = 60 * time.Second
		minSleep        = 10 * time.Second
		maxRetryBackoff = 5 // Cap retry backoff to 5 attempts
	)

	var (
		successCount int
		failCount    int
		sleepTime    = minSleep
	)

	ticker := time.NewTicker(sleepTime)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := OIDC(); err == nil {
				if !oidcInit {
					log.Println("OIDC provider initialized successfully")
				} else {
					log.Println("OIDC provider renewed successfully")
				}
				oidcInit = true
				failCount = 0
				successCount++
				// TODO will enable in production
				// Exponential backoff with a cap
				// sleepTime = minSleep * time.Duration(successCount)
				if sleepTime > maxSleep {
					// TODO will enable in production
					// sleepTime = maxSleep
				}

			} else {
				oidcInit = false
				successCount = 0
				failCount++
				// Exponential backoff with a cap
				sleepTime = minSleep * time.Duration(failCount)
				if failCount > maxRetryBackoff {
					// TODO will enable in production
					// sleepTime = minSleep * time.Duration(maxRetryBackoff)
				}
				log.Printf("OIDC initialization failed: %v. Retrying in %v", err, sleepTime)
			}

			log.Printf("Waiting for %v before next check", sleepTime)
			ticker.Reset(sleepTime)
		}
	}
}
func CheckOIDCInit() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !oidcInit {
			log.Println("Provider is Offline")
			c.JSON(http.StatusServiceUnavailable, model.Result{Success: common_err.OIDC_OFFLINE, Message: "Authentik Server is Offline"})
			return
		}
		c.Next()
	}
}

// Use an init function to initialize the oauth2Config variable.
func OIDC() error {
	authentik, err := service.MyService.Authentik().GetSettings()
	if (authentik != model2.AuthentikCredentialsDBModel{} && err == nil) {
		clientID = authentik.ClientID
		clientSecret = authentik.ClientSecret
		authServer = authentik.Issuer
		authURL = authentik.AuthUrl
		callbackURL = authentik.CallbackUrl
	}
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, authURL)
	if err != nil {
		return err
	}
	oauth2Config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  callbackURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "offline_access", "goauthentik.io/api"},
		//add offline access for refresh token
	}
	return nil
}
func GetOIDCSettings(c *gin.Context) {
	authentik, err := service.MyService.Authentik().GetSettings()
	if err != nil {
		c.JSON(common_err.SERVICE_ERROR,
			model.Result{
				Success: common_err.SERVICE_ERROR,
				Message: common_err.GetMsg(common_err.SERVICE_ERROR),
			})
		return
	}
	c.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data:    authentik,
		})
	return
}
func OIDCLogin(c *gin.Context) {
	json := make(map[string]string)
	c.ShouldBind(&json)
	state := json["state"]
	callBackUrl := fmt.Sprintf("%s/%s", json["baseUrl"], "v1/users/oidc/callback")

	oauth2Config.RedirectURL = callBackUrl
	c.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data:    oauth2Config.AuthCodeURL(state),
		})
}
func SaveOIDCSettings(c *gin.Context) {
	var oidcSetting OIDCSetting
	var authentik model2.AuthentikCredentialsDBModel
	c.ShouldBind(&oidcSetting)
	authentik.ClientID = oidcSetting.Settings.ClientID
	authentik.ClientSecret = oidcSetting.Settings.ClientSecret
	authentik.Issuer = oidcSetting.Settings.Issuer
	authentik.AuthUrl = oidcSetting.Settings.AuthURL
	authentik.CallbackUrl = oidcSetting.Settings.CallbackURL
	var result, err = service.MyService.Authentik().UpdateSettings(authentik)
	if err != nil {
		c.JSON(common_err.SERVICE_ERROR,
			model.Result{
				Success: common_err.SERVICE_ERROR,
				Message: common_err.GetMsg(common_err.SERVICE_ERROR),
			})
	}
	c.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data:    result,
		})
}
func OIDCCallback(c *gin.Context) {
	w := c.Writer
	r := c.Request

	// Verify state cookie
	state := c.Query("state")

	if r.URL.Query().Get("state") != state {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}

	// Exchange authorization code for token
	oauth2Token, err := oauth2Config.Exchange(context.Background(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	expiryDuration := time.Until(oauth2Token.Expiry)
	c.SetCookie("authentik_accessToken", oauth2Token.AccessToken, int(expiryDuration.Seconds()), "/", "", false, true)
	// c.SetCookie("authentik_refreshToken", oauth2Token.RefreshToken, int(expiryDuration.Seconds()), "/", "", false, true)
	c.Redirect(http.StatusFound, state)
}
func OIDCUserInfo(c *gin.Context) {
	json := make(map[string]string)
	c.ShouldBind(&json)
	accessToken, err := c.Cookie("authentik_accessToken")

	if err != nil {
		c.Redirect(http.StatusFound, "/#/oidc")
	}
	authentikUser, err := service.MyService.Authentik().GetUserInfo(accessToken, authServer)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.Result{Success: common_err.ERROR_AUTH_TOKEN, Message: common_err.GetMsg(common_err.ERROR_AUTH_TOKEN)})
		return
	}
	c.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data:    authentikUser,
		})
}
func OIDCHealthCheck(c *gin.Context) {
	var status string
	status, err := service.MyService.Authentik().HealthCheck(authServer)
	if err != nil {
		c.JSON(http.StatusOK, model.Result{Success: common_err.OIDC_OFFLINE, Message: common_err.GetMsg(common_err.OIDC_OFFLINE), Data: "Offline"})
		return
	}
	if status == "Starting" {
		c.JSON(http.StatusOK, model.Result{Success: common_err.OIDC_STARTING, Message: common_err.GetMsg(common_err.OIDC_OFFLINE), Data: "Starting"})
		return
	}
	c.JSON(http.StatusOK, model.Result{Success: common_err.OIDC_LIVE, Message: common_err.GetMsg(common_err.OIDC_LIVE), Data: "Live"})
}
func OIDCValidateToken(c *gin.Context) {

	json := make(map[string]string)
	c.ShouldBind(&json)
	accessToken, err := c.Cookie("authentik_accessToken")
	if err != nil {
		c.Redirect(http.StatusFound, "/#/oidc")
	}
	var validateToken model2.AuthentikToken
	validateToken, err = service.MyService.Authentik().ValidateToken(clientID, clientSecret, accessToken, authServer)
	if err != nil {
		c.JSON(http.StatusUnauthorized, model.Result{Success: common_err.ERROR_AUTH_TOKEN, Message: common_err.GetMsg(common_err.ERROR_AUTH_TOKEN)})
		return
	}
	if !validateToken.Active {
		c.JSON(http.StatusUnauthorized, model.Result{Success: common_err.ERROR_AUTH_TOKEN, Message: common_err.GetMsg(common_err.ERROR_AUTH_TOKEN)})
		return
	}
	c.JSON(http.StatusOK, model.Result{Success: common_err.ERROR_AUTH_TOKEN, Message: common_err.GetMsg(common_err.ERROR_AUTH_TOKEN)})
}
func OIDCLogout(c *gin.Context) {
	json := make(map[string]string)
	c.ShouldBind(&json)
	flow := "/if/flow/default-authentication-flow/"
	next := "/application/o/authorize/"

	client := "client_id=" + clientID
	redirect_uri := "&redirect_uri=" + url.QueryEscape(callbackURL)
	response_type := "&response_type=code"
	scope := "&scope=openid+profile+email+" + url.QueryEscape("goauthentik.io/api")
	state := "&state=" + url.QueryEscape("/#/profile")
	fullURL := authServer + flow + "?" + "next=" + url.QueryEscape(next+"?"+client+redirect_uri+response_type+scope+state)

	c.JSON(http.StatusOK, model.Result{Success: common_err.ERROR_AUTH_TOKEN, Message: common_err.GetMsg(common_err.ERROR_AUTH_TOKEN), Data: fullURL})
}
func OIDCProfile(c *gin.Context) {
	if !oidcInit {
		c.Redirect(http.StatusFound, "/#/authentik-offline")
	}
	json := make(map[string]string)
	c.ShouldBind(&json)
	accessToken, err := c.Cookie("authentik_accessToken")
	if err != nil {
		c.Redirect(http.StatusFound, "/#/oidc")
	}
	// r := c.Request
	// Get Authentik user info
	authentikUser, err := service.MyService.Authentik().GetUserInfo(accessToken, authServer)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.Result{Success: common_err.ERROR_AUTH_TOKEN, Message: common_err.GetMsg(common_err.ERROR_AUTH_TOKEN)})
		return
	}

	// Handle user data in local database
	user := service.MyService.User().GetUserInfoByUserName(authentikUser.User.Username)
	if user.Id > 0 {
		// Update existing user
		user.Nickname = authentikUser.User.Username
		user.Email = authentikUser.User.Email
		user.Role = determineUserRole(authentikUser.User.IsSuperuser)
		user.Avatar = authentikUser.User.Avatar
		service.MyService.User().UpdateUser(user)
	} else {
		// Create new user
		user = model2.UserDBModel{
			Username: authentikUser.User.Username,
			Password: hashPassword(),
			Email:    authentikUser.User.Email,
			Role:     determineUserRole(authentikUser.User.IsSuperuser),
			Avatar:   authentikUser.User.Avatar,
		}
		user = service.MyService.User().CreateUser(user)
		if user.Id == 0 {
			c.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
			return
		}
	}

	// Generate tokens
	token, err := generateTokens(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: err.Error()})
		return
	}
	data := make(map[string]interface{}, 2)
	data["token"] = token
	data["user"] = user
	data["authToken"] = accessToken
	c.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data:    data,
		})

}
func determineUserRole(isSuperuser bool) string {
	if isSuperuser {
		return "admin"
	}
	return "user"
}
func OnePanelHealthCheck(c *gin.Context) {
	status, err := service.MyService.OnePanel().HealthCheck(onePanelServer)
	if err != nil || status == "Offline" {
		c.JSON(http.StatusOK, model.Result{Success: common_err.OIDC_OFFLINE, Message: common_err.GetMsg(common_err.OIDC_OFFLINE), Data: "Offline"})
		return
	}
	c.JSON(http.StatusOK, model.Result{Success: common_err.OIDC_LIVE, Message: common_err.GetMsg(common_err.OIDC_LIVE), Data: "Live"})
}

func hashPassword() string {
	generatePassword, err := randString(16)
	if err != nil {
		return ""
	}
	return encryption.GetMD5ByStr(generatePassword)
}

func generateTokens(user model2.UserDBModel) (system_model.VerifyInformation, error) {
	privateKey, _ := service.MyService.User().GetKeyPair()

	accessToken, err := jwt.GetAccessToken(user.Username, privateKey, user.Id)
	if err != nil {
		return system_model.VerifyInformation{}, err
	}

	refreshToken, err := jwt.GetRefreshToken(user.Username, privateKey, user.Id)
	if err != nil {
		return system_model.VerifyInformation{}, err
	}

	return system_model.VerifyInformation{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(3 * time.Hour * time.Duration(1)).Unix(),
	}, nil
}

// func setCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string) {
// 	c := &http.Cookie{
// 		Name:     name,
// 		Value:    value,
// 		MaxAge:   int(time.Hour.Seconds()),
// 		Secure:   r.TLS != nil,
// 		HttpOnly: true,
// 	}
// 	http.SetCookie(w, c)
// }

// @Summary login user to openmediavault
// @Produce  application/json
// @Tags user
// @Param username password
// @Security SessionID
// @Success 200 {string} string "ok"
// @Router /users/omvLogin [post]
func PostOMVLogin(c *gin.Context) {
	if !limiter.Allow() {
		c.JSON(common_err.TOO_MANY_REQUEST,
			model.Result{
				Success: common_err.TOO_MANY_LOGIN_REQUESTS,
				Message: common_err.GetMsg(common_err.TOO_MANY_LOGIN_REQUESTS),
			})
		return
	}

	json := make(map[string]string)
	c.ShouldBind(&json)
	username := json["username"]
	password := json["password"]
	res, cookies := service.MyService.OMV().LoginSession(username, password)
	var resData model2.OMVLogin
	err := json2.Unmarshal([]byte(res), &resData)

	if err != nil {
		log.Printf("Error getting user: %v", err)
		return
	}

	if !resData.Response.Authenticated {
		c.JSON(common_err.CLIENT_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST_OR_PWD_INVALID, Message: common_err.GetMsg(common_err.USER_NOT_EXIST_OR_PWD_INVALID)})
		return
	}

	getUser, err := service.MyService.OMV().AuthUser(username, password, resData.Response.SessionID)
	if err != nil {
		// Handle the error, for example, log it or return it
		log.Printf("Error getting user: %v", err)
		return // or handle it in a way that fits your application's error handling strategy
	}
	var userData model2.OMVUser
	err = json2.Unmarshal([]byte(getUser), &userData)

	if err != nil {
		// Handle the error, for example, log it or return it
		log.Printf("Error getting user: %v", err)
		return // or handle it in a way that fits your application's error handling strategy
	}

	if isEmpty(userData.Response) {
		c.JSON(common_err.CLIENT_ERROR,
			model.Result{
				Success: common_err.USER_NOT_EXIST_OR_PWD_INVALID,
				Message: common_err.GetMsg(common_err.USER_NOT_EXIST_OR_PWD_INVALID)})
		return
	}
	// cookie_value, err := c.Cookie("sessionID")
	// decrypt := encryption.Decrypt(cookie_value)
	// fmt.Printf(decrypt)
	// sessionId := encryption.Encrypt(resData.Response.SessionID)
	for _, cookie := range cookies {
		c.SetCookie(cookie.Name, cookie.Value, 3600, "/", "", false, true)
	}
	c.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data:    userData,
		})

}
func PostLogout(c *gin.Context) {
	cookies := c.Request.Cookies()
	for _, cookie := range cookies {
		// Set the cookie to expire immediately
		c.SetCookie(cookie.Name, "", -1, "/", "", false, true)
	}
	c.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
		})
}

func isEmpty(obj interface{}) bool {
	jsonData, err := json.Marshal(obj)
	if err != nil && string(jsonData) == "{}" {
		return true
	}
	return false
}

// @Summary edit user head
// @Produce  application/json
// @Accept multipart/form-data
// @Tags user
// @Param file formData file true "用户头像"
// @Security ApiKeyAuth
// @Success 200 {string} string "ok"
// @Router /users/avatar [put]
func PutUserAvatar(c *gin.Context) {
	id := c.GetHeader("user_id")
	user := service.MyService.User().GetUserInfoById(id)
	if user.Id == 0 {
		c.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
		return
	}
	json := make(map[string]string)
	c.ShouldBind(&json)

	data := json["file"]
	imgBase64 := strings.Replace(data, "data:image/png;base64,", "", 1)
	decodeData, err := base64.StdEncoding.DecodeString(string(imgBase64))
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: err.Error()})
		return
	}

	// 将字节数组转为图片
	img, _, err := image.Decode(strings.NewReader(string(decodeData)))
	if err != nil {
		log.Fatal(err)
	}

	ext := ".png"
	avatarPath := config.AppInfo.UserDataPath + "/" + id + "/avatar" + ext
	os.Remove(avatarPath)
	outFile, err := os.Create(avatarPath)
	if err != nil {
		logger.Error("create file error", zap.Error(err))
	}
	defer outFile.Close()

	err = png.Encode(outFile, img)
	if err != nil {
		logger.Error("encode error", zap.Error(err))
	}
	user.Avatar = avatarPath
	service.MyService.User().UpdateUser(user)
	c.JSON(http.StatusOK,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data:    user,
		})
}

// @Summary get user head
// @Produce  application/json
// @Tags user
// @Param file formData file true "用户头像"
// @Security ApiKeyAuth
// @Success 200 {string} string "ok"
// @Router /users/avatar [get]
func GetUserAvatar(c *gin.Context) {
	id := c.GetHeader("user_id")
	user := service.MyService.User().GetUserInfoById(id)
	if user.Id == 0 {
		c.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
		return
	}

	if file.Exists(user.Avatar) {
		c.Header("Content-Disposition", "attachment; filename*=utf-8''"+url2.PathEscape(path.Base(user.Avatar)))
		c.Header("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate, value")
		c.File(user.Avatar)
		return
	}
	user.Avatar = "/usr/share/casaos/www/avatar.svg"
	if file.Exists(user.Avatar) {
		c.Header("Content-Disposition", "attachment; filename*=utf-8''"+url2.PathEscape(path.Base(user.Avatar)))
		c.Header("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate, value")
		c.File(user.Avatar)
		return
	}
	user.Avatar = "/var/lib/casaos/www/avatar.svg"
	c.Header("Content-Disposition", "attachment; filename*=utf-8''"+url2.PathEscape(path.Base(user.Avatar)))
	c.Header("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate, value")
	c.File(user.Avatar)
}

// @Summary edit user name
// @Produce  application/json
// @Accept application/json
// @Tags user
// @Param old_name  query string true "Old user name"
// @Security ApiKeyAuth
// @Success 200 {string} string "ok"
// @Router /user/name/:id [put]
func PutUserInfo(c *gin.Context) {
	id := c.GetHeader("user_id")
	json := model2.UserDBModel{}
	c.ShouldBind(&json)
	user := service.MyService.User().GetUserInfoById(id)
	if user.Id == 0 {
		c.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST_OR_PWD_INVALID, Message: common_err.GetMsg(common_err.USER_NOT_EXIST_OR_PWD_INVALID)})
		return
	}
	if len(json.Username) > 0 {
		u := service.MyService.User().GetUserInfoByUserName(json.Username)
		if u.Id > 0 {
			c.JSON(common_err.CLIENT_ERROR,
				model.Result{Success: common_err.USER_EXIST, Message: common_err.GetMsg(common_err.USER_EXIST)})
			return
		}
	}

	if len(json.Email) == 0 {
		json.Email = user.Email
	}
	if len(json.Avatar) == 0 {
		json.Avatar = user.Avatar
	}
	if len(json.Role) == 0 {
		json.Role = user.Role
	}
	if len(json.Description) == 0 {
		json.Description = user.Description
	}
	if len(json.Nickname) == 0 {
		json.Nickname = user.Nickname
	}
	service.MyService.User().UpdateUser(json)
	c.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: json})
}

// @Summary edit user password
// @Produce  application/json
// @Accept application/json
// @Tags user
// @Security ApiKeyAuth
// @Success 200 {string} string "ok"
// @Router /user/password/:id [put]
func PutUserPassword(c *gin.Context) {
	id := c.GetHeader("user_id")
	json := make(map[string]string)
	c.ShouldBind(&json)
	oldPwd := json["old_password"]
	pwd := json["password"]
	if len(oldPwd) == 0 || len(pwd) == 0 {
		c.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
		return
	}
	user := service.MyService.User().GetUserAllInfoById(id)
	if user.Id == 0 {
		c.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
		return
	}
	if user.Password != encryption.GetMD5ByStr(oldPwd) {
		c.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.PWD_INVALID_OLD, Message: common_err.GetMsg(common_err.PWD_INVALID_OLD)})
		return
	}
	user.Password = encryption.GetMD5ByStr(pwd)
	service.MyService.User().UpdateUserPassword(user)
	user.Password = ""
	c.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: user})
}

// @Summary edit user nick
// @Produce  application/json
// @Accept application/json
// @Tags user
// @Param nick_name query string false "nick name"
// @Security ApiKeyAuth
// @Success 200 {string} string "ok"
// @Router /user/nick [put]
func PutUserNick(c *gin.Context) {
	id := c.GetHeader("user_id")
	json := make(map[string]string)
	c.ShouldBind(&json)
	Nickname := json["nick_name"]
	if len(Nickname) == 0 {
		c.JSON(http.StatusOK, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
		return
	}
	user := service.MyService.User().GetUserInfoById(id)
	if user.Id == 0 {
		c.JSON(http.StatusOK,
			model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
		return
	}
	user.Nickname = Nickname
	service.MyService.User().UpdateUser(user)
	c.JSON(http.StatusOK, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: user})
}

// @Summary edit user description
// @Produce  application/json
// @Accept multipart/form-data
// @Tags user
// @Param description formData string false "Description"
// @Security ApiKeyAuth
// @Success 200 {string} string "ok"
// @Router /user/desc [put]
func PutUserDesc(c *gin.Context) {
	id := c.GetHeader("user_id")
	json := make(map[string]string)
	c.ShouldBind(&json)
	desc := json["description"]
	if len(desc) == 0 {
		c.JSON(http.StatusOK, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
		return
	}
	user := service.MyService.User().GetUserInfoById(id)
	if user.Id == 0 {
		c.JSON(http.StatusOK,
			model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
		return
	}
	user.Description = desc

	service.MyService.User().UpdateUser(user)

	c.JSON(http.StatusOK, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: user})
}

// @Summary get user info
// @Produce  application/json
// @Accept  application/json
// @Tags user
// @Success 200 {string} string "ok"
// @Router /user/info/:id [get]
func GetUserInfo(c *gin.Context) {
	id := c.GetHeader("user_id")
	user := service.MyService.User().GetUserInfoById(id)

	c.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data:    user,
		})
}

/**
 * @description:
 * @param {*gin.Context} c
 * @param {string} Username
 * @return {*}
 * @method:
 * @router:
 */
func GetUserInfoByUsername(c *gin.Context) {
	username := c.Param("username")
	if len(username) == 0 {
		c.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
		return
	}
	user := service.MyService.User().GetUserInfoByUserName(username)
	if user.Id == 0 {
		c.JSON(common_err.SUCCESS,
			model.Result{
				Success: common_err.SUCCESS,
				Message: common_err.GetMsg(common_err.USER_NOT_EXIST),
				Data:    nil,
			})
		return
	}

	c.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data:    user,
		})
}

/**
 * @description: get all Usernames
 * @method:GET
 * @router:/user/all/name
 */
func GetUserAllUsername(c *gin.Context) {
	users := service.MyService.User().GetAllUserName()
	names := []string{}
	for _, v := range users {
		names = append(names, v.Username)
	}
	c.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data:    names,
		})
}

/**
 * @description:get custom file by user
 * @param {path} name string "file name"
 * @method: GET
 * @router: /user/custom/:key
 */
func GetUserCustomConf(c *gin.Context) {
	name := c.Param("key")
	if len(name) == 0 {
		c.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
		return
	}
	id := c.GetHeader("user_id")

	user := service.MyService.User().GetUserInfoById(id)
	//	user := service.MyService.User().GetUserInfoByUsername(Username)
	if user.Id == 0 {
		c.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
		return
	}
	filePath := config.AppInfo.UserDataPath + "/" + id + "/" + name + ".json"

	data := file.ReadFullFile(filePath)
	if !gjson.ValidBytes(data) {
		c.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: string(data)})
		return
	}
	c.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: json2.RawMessage(string(data))})
}

/**
 * @description:create or update custom conf by user
 * @param {path} name string "file name"
 * @method:POST
 * @router:/user/custom/:key
 */
func PostUserCustomConf(c *gin.Context) {
	name := c.Param("key")
	if len(name) == 0 {
		c.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
		return
	}
	id := c.GetHeader("user_id")
	user := service.MyService.User().GetUserInfoById(id)
	if user.Id == 0 {
		c.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
		return
	}
	data, _ := io.ReadAll(c.Request.Body)
	filePath := config.AppInfo.UserDataPath + "/" + strconv.Itoa(user.Id)

	if err := file.IsNotExistMkDir(filePath); err != nil {
		c.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
		return
	}

	if err := file.WriteToPath(data, filePath, name+".json"); err != nil {
		c.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
		return
	}

	if name == "system" {
		dataMap := make(map[string]string, 1)
		dataMap["system"] = string(data)
		response, err := service.MyService.MessageBus().PublishEventWithResponse(context.Background(), common.SERVICENAME, "zimaos:user:save_config", dataMap)
		if err != nil {
			logger.Error("failed to publish event to message bus", zap.Error(err), zap.Any("event", string(data)))
			return
		}
		if response.StatusCode() != http.StatusOK {
			logger.Error("failed to publish event to message bus", zap.String("status", response.Status()), zap.Any("response", response))
		}

	}

	c.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: json2.RawMessage(string(data))})
}

/**
 * @description: delete user custom config
 * @param {path} key string
 * @method:delete
 * @router:/user/custom/:key
 */
func DeleteUserCustomConf(c *gin.Context) {
	name := c.Param("key")
	if len(name) == 0 {
		c.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
		return
	}
	id := c.GetHeader("user_id")
	user := service.MyService.User().GetUserInfoById(id)
	if user.Id == 0 {
		c.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
		return
	}
	filePath := config.AppInfo.UserDataPath + "/" + strconv.Itoa(user.Id) + "/" + name + ".json"
	err := os.Remove(filePath)
	if err != nil {
		c.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
		return
	}
	c.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS)})
}

/**
 * @description:
 * @param {path} id string "user id"
 * @method:DELETE
 * @router:/user/delete/:id
 */
func DeleteUser(c *gin.Context) {
	id := c.Param("id")
	service.MyService.User().DeleteUserById(id)
	c.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: id})
}

/**
 * @description:update user image
 * @method:POST
 * @router:/user/current/image/:key
 */
func PutUserImage(c *gin.Context) {
	id := c.GetHeader("user_id")
	json := make(map[string]string)
	c.ShouldBind(&json)

	path := json["path"]
	key := c.Param("key")
	if len(path) == 0 || len(key) == 0 {
		c.JSON(http.StatusOK, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
		return
	}
	if !file.Exists(path) {
		c.JSON(http.StatusOK, model.Result{Success: common_err.FILE_DOES_NOT_EXIST, Message: common_err.GetMsg(common_err.FILE_DOES_NOT_EXIST)})
		return
	}

	_, err := file.GetImageExt(path)
	if err != nil {
		c.JSON(http.StatusOK, model.Result{Success: common_err.NOT_IMAGE, Message: common_err.GetMsg(common_err.NOT_IMAGE)})
		return
	}

	user := service.MyService.User().GetUserInfoById(id)
	if user.Id == 0 {
		c.JSON(http.StatusOK, model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
		return
	}
	fstat, _ := os.Stat(path)
	if fstat.Size() > 10<<20 {
		c.JSON(http.StatusOK, model.Result{Success: common_err.IMAGE_TOO_LARGE, Message: common_err.GetMsg(common_err.IMAGE_TOO_LARGE)})
		return
	}
	ext := file.GetExt(path)
	filePath := config.AppInfo.UserDataPath + "/" + strconv.Itoa(user.Id) + "/" + key + ext
	file.CopySingleFile(path, filePath, "overwrite")

	data := make(map[string]string, 3)
	data["path"] = filePath
	data["file_name"] = key + ext
	data["online_path"] = "/v1/users/image?path=" + filePath
	c.JSON(http.StatusOK, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: data})
}

/**
* @description:
* @param {*gin.Context} c
* @param {file} file
* @param {string} key
* @param {string} type:avatar,background
* @return {*}
* @method:
* @router:
 */
func PostUserUploadImage(c *gin.Context) {
	id := c.GetHeader("user_id")
	f, err := c.FormFile("file")
	key := c.Param("key")
	t := c.PostForm("type")
	if len(key) == 0 {
		c.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
		return
	}
	if err != nil {
		c.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.CLIENT_ERROR, Message: common_err.GetMsg(common_err.CLIENT_ERROR), Data: err.Error()})
		return
	}

	_, err = file.GetImageExtByName(f.Filename)
	if err != nil {
		c.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.NOT_IMAGE, Message: common_err.GetMsg(common_err.NOT_IMAGE)})
		return
	}
	ext := filepath.Ext(f.Filename)
	user := service.MyService.User().GetUserInfoById(id)

	if user.Id == 0 {
		c.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
		return
	}
	if t == "avatar" {
		key = "avatar"
	}
	path := config.AppInfo.UserDataPath + "/" + strconv.Itoa(user.Id) + "/" + key + ext

	c.SaveUploadedFile(f, path)
	data := make(map[string]string, 3)
	data["path"] = path
	data["file_name"] = key + ext
	data["online_path"] = "/v1/users/image?path=" + path
	c.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: data})
}

/**
 * @description: get current user's image
 * @method:GET
 * @router:/user/image/:id
 */
func GetUserImage(c *gin.Context) {
	filePath := c.Query("path")
	if len(filePath) == 0 {
		c.JSON(http.StatusNotFound, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
		return
	}
	absFilePath, err := filepath.Abs(filepath.Clean(filePath))
	if err != nil {
		c.JSON(http.StatusNotFound, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
		return
	}
	if !file.Exists(absFilePath) {
		c.JSON(http.StatusNotFound, model.Result{Success: common_err.FILE_DOES_NOT_EXIST, Message: common_err.GetMsg(common_err.FILE_DOES_NOT_EXIST)})
		return
	}
	if !strings.Contains(absFilePath, config.AppInfo.UserDataPath) {
		c.JSON(http.StatusNotFound, model.Result{Success: common_err.INSUFFICIENT_PERMISSIONS, Message: common_err.GetMsg(common_err.INSUFFICIENT_PERMISSIONS)})
		return
	}

	matched, err := regexp.MatchString(`^/var/lib/casaos/\d`, absFilePath)
	if err != nil {
		c.JSON(http.StatusNotFound, model.Result{Success: common_err.INSUFFICIENT_PERMISSIONS, Message: common_err.GetMsg(common_err.INSUFFICIENT_PERMISSIONS)})
		return
	}
	if !matched {
		c.JSON(http.StatusNotFound, model.Result{Success: common_err.INSUFFICIENT_PERMISSIONS, Message: common_err.GetMsg(common_err.INSUFFICIENT_PERMISSIONS)})
		return
	}

	fileName := path.Base(absFilePath)

	// @tiger - RESTful 规范下不应该返回文件本身内容，而是返回文件的静态URL，由前端去解析
	c.Header("Content-Disposition", "attachment; filename*=utf-8''"+url2.PathEscape(fileName))
	c.File(absFilePath)
}

func DeleteUserImage(c *gin.Context) {
	id := c.GetHeader("user_id")
	path := c.Query("path")
	if len(path) == 0 {
		c.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
		return
	}
	user := service.MyService.User().GetUserInfoById(id)
	if user.Id == 0 {
		c.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
		return
	}
	if !file.Exists(path) {
		c.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.FILE_DOES_NOT_EXIST, Message: common_err.GetMsg(common_err.FILE_DOES_NOT_EXIST)})
		return
	}
	if !strings.Contains(path, config.AppInfo.UserDataPath+"/"+strconv.Itoa(user.Id)) {
		c.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.INSUFFICIENT_PERMISSIONS, Message: common_err.GetMsg(common_err.INSUFFICIENT_PERMISSIONS)})
		return
	}
	os.Remove(path)
	c.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS)})
}

/**
 * @description:
 * @param {*gin.Context} c
 * @param {string} refresh_token
 * @return {*}
 * @method:
 * @router:
 */
func PostUserRefreshToken(c *gin.Context) {
	js := make(map[string]string)
	c.ShouldBind(&js)
	refresh := js["refresh_token"]

	privateKey, _ := service.MyService.User().GetKeyPair()

	claims, err := jwt.ParseToken(
		refresh,
		func() (*ecdsa.PublicKey, error) {
			_, publicKey := service.MyService.User().GetKeyPair()
			return publicKey, nil
		})
	if err != nil {
		c.JSON(http.StatusUnauthorized, model.Result{Success: common_err.VERIFICATION_FAILURE, Message: common_err.GetMsg(common_err.VERIFICATION_FAILURE), Data: err.Error()})
		return
	}
	if !claims.VerifyExpiresAt(time.Now(), true) || !claims.VerifyIssuer("refresh", true) {
		c.JSON(http.StatusUnauthorized, model.Result{Success: common_err.VERIFICATION_FAILURE, Message: common_err.GetMsg(common_err.VERIFICATION_FAILURE)})
		return
	}

	newAccessToken, err := jwt.GetAccessToken(claims.Username, privateKey, claims.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: err.Error()})
		return
	}

	newRefreshToken, err := jwt.GetRefreshToken(claims.Username, privateKey, claims.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: err.Error()})
		return
	}

	verifyInfo := system_model.VerifyInformation{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    time.Now().Add(3 * time.Hour).Unix(),
	}

	c.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: verifyInfo})
}

func DeleteUserAll(c *gin.Context) {
	service.MyService.User().DeleteAllUser()
	c.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS)})
}

// @Summary 检查是否进入引导状态
// @Produce  application/json
// @Accept application/json
// @Tags sys
// @Security ApiKeyAuth
// @Success 200 {string} string "ok"
// @Router /sys/init/check [get]
// func GetUserStatus(c *gin.Context) {
// 	data := make(map[string]interface{}, 2)

// 	if service.MyService.User().GetUserCount() > 0 {
// 		data["initialized"] = true
// 		data["key"] = ""
// 	} else {
// 		key := uuid.NewV4().String()
// 		service.UserRegisterHash[key] = key
// 		data["key"] = key
// 		data["initialized"] = false
// 	}
// 	gpus, err := external.NvidiaGPUInfoList()
// 	if err != nil {
// 		logger.Error("NvidiaGPUInfoList error", zap.Error(err))
// 	}
// 	data["gpus"] = len(gpus)
// 	c.JSON(common_err.SUCCESS,
// 		model.Result{
// 			Success: common_err.SUCCESS,
// 			Message: common_err.GetMsg(common_err.SUCCESS),
// 			Data:    data,
// 		})
// }

func GetUserStatus(c *gin.Context) {
	data := make(map[string]interface{}, 2)
	key := uuid.NewV4().String()
	service.UserRegisterHash[key] = key
	data["key"] = key
	data["initialized"] = true
	gpus, err := external.NvidiaGPUInfoList()
	if err != nil {
		logger.Error("NvidiaGPUInfoList error", zap.Error(err))
	}
	data["gpus"] = len(gpus)
	c.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data:    data,
		})
}
