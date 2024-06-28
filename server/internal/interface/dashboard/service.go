package dashboard

import (
	"context"
	"net/http"
	"strings"

	"github.com/a-h/templ"
	"github.com/ark-network/ark/internal/core/application"
	"github.com/gin-gonic/gin/render"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

const userkey = "admin"

var secret = []byte("secret_session_key_should_be_passed_by_env") // TODO

func init() {
	gin.SetMode(gin.ReleaseMode)
}

// templRender implements the render.Render interface.
type templRender struct {
	Code int
	Data templ.Component
}

// Render implements the render.Render interface.
func (t templRender) Render(w http.ResponseWriter) error {
	t.WriteContentType(w)
	w.WriteHeader(t.Code)
	if t.Data != nil {
		return t.Data.Render(context.Background(), w)
	}
	return nil
}

// WriteContentType implements the render.Render interface.
func (t templRender) WriteContentType(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
}

// Instance implements the render.Render interface.
func (t *templRender) Instance(name string, data interface{}) render.Render {
	if templData, ok := data.(templ.Component); ok {
		return &templRender{
			Code: http.StatusOK,
			Data: templData,
		}
	}
	return nil
}

// AuthRequired is a simple middleware to check the session.
func AuthRequired(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get(userkey)
	if user == nil {
		// Abort the request with the appropriate error code
		c.Redirect(http.StatusTemporaryRedirect, "/dashboard/login")
		return
	}
	// Continue down the chain to handler etc
	c.Next()
}

// authenticate is a handler that parses a form and checks for specific data.
func authenticate(c *gin.Context) {
	session := sessions.Default(c)
	username := c.PostForm("username")
	password := c.PostForm("password")

	// Validate form input
	if strings.Trim(username, " ") == "" || strings.Trim(password, " ") == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Parameters can't be empty"})
		return
	}

	// Check for username and password match, usually from a database
	if username != "hello" || password != "itsme" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed"})
		return
	}

	// Save the username in the session
	session.Set(userkey, username) // In real world usage you'd set this to the users ID
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
		return
	}
	c.Header("HX-Redirect", "/dashboard")
	c.JSON(http.StatusOK, gin.H{"message": "Successfully authenticated user"})
}

// logout is the handler called for the user to log out.
func logout(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get(userkey)
	if user == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session token"})
		return
	}
	session.Delete(userkey)
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
		return
	}
	c.Header("HX-Redirect", "/dashboard/login")
	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
}

type service struct {
	*gin.Engine
	adminSvc application.AdminService
}

func NewService(adminSvc application.AdminService) *service {
	// Create a new Fiber server.
	router := gin.Default()

	// Define HTML renderer for template engine.
	router.HTMLRender = &templRender{}

	svc := &service{router, adminSvc}

	// Setup the cookie store for session management
	svc.Use(sessions.Sessions("mysession", cookie.NewStore(secret)))

	// Handle static files.
	svc.Static("/static", "./static")

	// Login and logout routes
	svc.POST("/authenticate", authenticate)
	svc.GET("/login", svc.loginViewHandler)
	svc.GET("/logout", logout)

	private := svc.Group("/")
	private.Use(AuthRequired)

	// Handle index page view.
	private.GET("/", svc.indexViewHandler)

	// Handle sweeps page view.
	private.GET("/sweeps", svc.sweepsViewHandler)

	// Handle rounds page view.
	private.GET("/rounds", svc.roundsViewHandler)

	// Handle rounds page view.
	private.GET("/round/:txid", svc.roundViewHandler)

	// Handle vtxo page view.
	// TODO: Plug admin service once we have a method to list vtxos
	// or drop if we don't want such feature.
	private.GET("/vtxo/:outpoint", vtxoViewHandler)

	return svc
}
