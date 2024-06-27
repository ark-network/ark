package dashboard

import (
	"net/http"
	"time"

	"github.com/a-h/templ"
	"github.com/angelofallars/htmx-go"

	"github.com/ark-network/ark/internal/core/application"
	"github.com/ark-network/ark/internal/interface/dashboard/templates"
	"github.com/ark-network/ark/internal/interface/dashboard/templates/pages"

	"github.com/gin-gonic/gin"
)

func viewHandler(bodyContent templ.Component, c *gin.Context) {
	indexTemplate := templates.Layout(bodyContent)
	// Render index page template.
	if err := htmx.NewResponse().RenderTempl(c.Request.Context(), c.Writer, indexTemplate); err != nil {
		// If not, return HTTP 500 error.
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
}

// indexViewHandler handles a view for the index page: '/'
func (svc *service) indexViewHandler(c *gin.Context) {
	ctx := c.Request.Context()
	balance, err := svc.adminSvc.GetBalance(ctx)
	if err != nil {
		// TODO: handle
	}
	nextSweeps, err := svc.adminSvc.GetScheduledSweeps(ctx)
	if err != nil {
		// TODO: handle
	}
	now := time.Now()
	oneHourAgo := now.Add(-time.Hour)
	lastRounds, err := svc.adminSvc.GetRounds(ctx, oneHourAgo.Unix(), now.Unix())
	if err != nil {
		// TODO: handle
	}

	var round *application.RoundDetails
	if len(lastRounds) > 0 {
		round, _ = svc.adminSvc.GetRoundDetails(ctx, lastRounds[0])
	}
	bodyContent := pages.HomeBodyContent(
		balance, nextSweeps, lastRounds, round,
	)
	viewHandler(bodyContent, c)
}

// sweepsViewHandler handles a view for the sweeps page: '/sweeps'
func (svc *service) sweepsViewHandler(c *gin.Context) {
	nextSweeps, err := svc.adminSvc.GetScheduledSweeps(c.Request.Context())
	if err != nil {
		// TODO: handle
	}
	bodyContent := pages.SweepsBodyContent(nextSweeps)
	viewHandler(bodyContent, c)
}

// roundsViewHandler handles a view for the rounds page: '/rounds'
func (svc *service) roundsViewHandler(c *gin.Context) {
	lastRounds, err := svc.adminSvc.GetRounds(c.Request.Context(), 0, 0)
	if err != nil {
		// TODO: handle
	}
	bodyContent := pages.RoundsBodyContent(lastRounds)
	viewHandler(bodyContent, c)
}

// roundViewHandler handles a view for the round page: '/round/:txid'
func (svc *service) roundViewHandler(c *gin.Context) {
	round, err := svc.adminSvc.GetRoundDetails(c.Request.Context(), c.Param("txid"))
	if err != nil {
		// TODO: handle
	}
	bodyContent := pages.RoundBodyContent(*round)
	viewHandler(bodyContent, c)
}

// vtxoViewHandler handles a view for the vtxo page: '/vtxo/:outpoint'
func vtxoViewHandler(c *gin.Context) {
	bodyContent := pages.VtxoBodyContent(c.Param(("outpoint")))
	viewHandler(bodyContent, c)
}
