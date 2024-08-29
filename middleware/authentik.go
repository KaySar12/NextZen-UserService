package middleware

import (
	"log"

	"github.com/gin-gonic/gin"
)

func CheckConnection() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Println("OK")
		c.Next()
	}
}
