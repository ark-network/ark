package dashboard

import (
	"context"
	"net/http"

	"github.com/a-h/templ"
	"github.com/ark-network/ark/internal/core/application"
	"github.com/gin-gonic/gin/render"

	"github.com/gin-gonic/gin"
)

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
	// Handle static files.
	svc.Static("/static", "./static")

	// Handle index page view.
	svc.GET("/", svc.indexViewHandler)

	// Handle sweeps page view.
	svc.GET("/sweeps", svc.sweepsViewHandler)

	// Handle rounds page view.
	svc.GET("/rounds", svc.roundsViewHandler)

	// Handle rounds page view.
	svc.GET("/round/:txid", svc.roundViewHandler)

	// Handle vtxo page view.
	// TODO: Plug admin service once we have a method to list vtxos
	// or drop if we don't want such feature.
	svc.GET("/vtxo/:outpoint", vtxoViewHandler)

	return svc
}
