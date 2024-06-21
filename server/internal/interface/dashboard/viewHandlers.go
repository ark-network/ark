package main

import (
	"net/http"

	"github.com/a-h/templ"
	"github.com/angelofallars/htmx-go"

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
func indexViewHandler(c *gin.Context) {
	bodyContent := pages.HomeBodyContent(
		getBalance(),
		getNextSweeps(),
		getRoundDetails(),
		getLastRounds(),
	)
	viewHandler(bodyContent, c)
}

// sweepsViewHandler handles a view for the sweeps page: '/sweeps'
func sweepsViewHandler(c *gin.Context) {
	bodyContent := pages.SweepsBodyContent(getNextSweeps())
	viewHandler(bodyContent, c)
}

// roundsViewHandler handles a view for the rounds page: '/rounds'
func roundsViewHandler(c *gin.Context) {
	bodyContent := pages.RoundsBodyContent(getLastRounds())
	viewHandler(bodyContent, c)
}

// roundViewHandler handles a view for the round page: '/round/:txid'
func roundViewHandler(c *gin.Context) {
	bodyContent := pages.RoundBodyContent(getRoundDetails(c.Param("txid")))
	viewHandler(bodyContent, c)
}
