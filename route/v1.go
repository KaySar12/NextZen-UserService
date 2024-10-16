package route

import (
	"crypto/ecdsa"
	"os"

	"github.com/KaySar12/NextZen-Common/middleware"
	"github.com/KaySar12/NextZen-Common/utils/jwt"
	v1 "github.com/KaySar12/NextZen-UserService/route/v1"
	"github.com/KaySar12/NextZen-UserService/service"
	"github.com/gin-contrib/gzip"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func InitRouter() *gin.Engine {
	r := gin.Default()
	r.Use(middleware.Cors())
	r.Use(v1.CheckOIDCInit())
	r.Use(gzip.Gzip(gzip.DefaultCompression))

	store := cookie.NewStore([]byte("secret"))
	sessionMiddleware := sessions.Sessions("1Panel", store)
	r.Use(sessionMiddleware)
	// check if environment variable is set
	if ginMode, success := os.LookupEnv("GIN_MODE"); success {
		gin.SetMode(ginMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	go v1.InitOIDC()
	r.POST("/v1/users/register", v1.PostUserRegister)
	r.POST("/v1/users/login", v1.PostUserLogin)
	r.POST("/v1/users/omvlogin", v1.PostOMVLogin)
	r.POST("/v1/users/logout", v1.PostLogout)
	r.GET("/v1/users/name", v1.GetUserAllUsername) // all/name
	r.POST("/v1/users/refresh", v1.PostUserRefreshToken)
	r.GET("/v1/users/image", v1.GetUserImage)
	r.GET("/v1/users/:username", v1.GetUserInfoByUsername)
	r.GET("/v1/users/status", v1.GetUserStatus) // init/check
	r.POST("/v1/users/oidc/login", v1.OIDCLogin)
	r.GET("/v1/users/oidc/callback", v1.OIDCCallback)
	r.GET("/v1/users/oidc/profile", v1.OIDCProfile)
	r.GET("/v1/users/oidc/userinfo", v1.OIDCUserInfo)
	r.POST("/v1/users/oidc/validateToken", v1.OIDCValidateToken)
	r.POST("/v1/users/oidc/logout", v1.OIDCLogout)
	r.GET("/v1/users/oidc/health", v1.OIDCHealthCheck)
	r.GET("/v1/users/oidc/settings", v1.GetOIDCSettings)
	r.POST("/v1/users/oidc/saveSettings", v1.SaveOIDCSettings)
	r.GET("/v1/1panel/health", v1.OnePanelHealthCheck)
	// r.POST("/v1/1panel/login", v1.OnePanelLogin)
	// r.POST("/v1/1panel/app/search", v1.ExternalAPIMiddleware, v1.OnePanelLogin)
	// r.POST("/v1/1panel/website/search", v1.ExternalAPIMiddleware, v1.OnePanelLogin)
	r.POST("/v1/1panel/website/create", v1.ExternalAPIMiddleware, v1.OnePanelCreateWebsite)
	r.POST("/v1/1panel/website/delete", v1.ExternalAPIMiddleware, v1.OnePanelDeleteWebsite)
	r.POST("/v1/1panel/website/update-proxy", v1.ExternalAPIMiddleware, v1.OnePanelUpdateProxyWebsite)
	v1Group := r.Group("/v1")

	v1Group.Use(jwt.JWT(
		func() (*ecdsa.PublicKey, error) {
			_, publicKey := service.MyService.User().GetKeyPair()
			return publicKey, nil
		},
	))
	{
		// v1OnePanel := v1Group.Group("/1panel")
		// v1OnePanel.Use()
		// {
		// 	r.GET("/health", v1.OnePanelHealthCheck)
		// 	r.POST("/login", v1.OnePanelLogin)
		// 	r.POST("/app/search", v1.ExternalAPIMiddleware, v1.OnePanelLogin)
		// 	r.POST("/website/search", v1.ExternalAPIMiddleware, v1.OnePanelLogin)
		// 	r.POST("/website/create", v1.ExternalAPIMiddleware, v1.OnePanelCreateWebsite)
		// }
		v1UsersGroup := v1Group.Group("/users")
		v1UsersGroup.Use()
		{
			v1UsersGroup.GET("/current", v1.GetUserInfo)
			v1UsersGroup.PUT("/current", v1.PutUserInfo)
			v1UsersGroup.PUT("/current/password", v1.PutUserPassword)

			v1UsersGroup.GET("/current/custom/:key", v1.GetUserCustomConf)
			v1UsersGroup.POST("/current/custom/:key", v1.PostUserCustomConf)
			v1UsersGroup.DELETE("/current/custom/:key", v1.DeleteUserCustomConf)

			v1UsersGroup.POST("/current/image/:key", v1.PostUserUploadImage)
			v1UsersGroup.PUT("/current/image/:key", v1.PutUserImage)
			// v1UserGroup.POST("/file/image/:key", v1.PostUserFileImage)
			v1UsersGroup.DELETE("/current/image", v1.DeleteUserImage)

			v1UsersGroup.PUT("/avatar", v1.PutUserAvatar)
			v1UsersGroup.GET("/avatar", v1.GetUserAvatar)

			v1UsersGroup.DELETE("/:id", v1.DeleteUser)
			// v1UsersGroup.GET("/:username", v1.GetUserInfoByUsername)
			v1UsersGroup.DELETE("", v1.DeleteUserAll)
		}
	}

	return r
}
