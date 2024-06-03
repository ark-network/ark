package main

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func main() {
	// Set up Viper for configuration
	viper.AutomaticEnv()

	// Set default values
	viper.SetDefault("WEB_DIR", "web")

	// Set up Logrus for logging
	log.SetFormatter(&log.TextFormatter{})
	log.SetOutput(os.Stdout)

	// Parse environment variables
	webDir := viper.GetString("WEB_DIR")

	router := gin.Default()
	router.LoadHTMLGlob(webDir + "/*")

	// API
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "home.html", gin.H{})
	})

	router.Run(":8080")
}
