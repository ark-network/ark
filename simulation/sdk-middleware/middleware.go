// middleware/middleware.go
package middleware

import (
	"context"
)

//go:generate go run generate_proxy.go
type Middleware interface {
	Before(ctx context.Context, methodName string, args []interface{}) context.Context
	After(ctx context.Context, methodName string, results []interface{}, err error)
}

type Chain struct {
	middlewares []Middleware
}

func NewChain(middlewares ...Middleware) *Chain {
	return &Chain{middlewares: middlewares}
}

func (c *Chain) Add(middleware Middleware) {
	c.middlewares = append(c.middlewares, middleware)
}

func (c *Chain) Before(ctx context.Context, methodName string, args []interface{}) context.Context {
	for _, m := range c.middlewares {
		ctx = m.Before(ctx, methodName, args)
	}
	return ctx
}

func (c *Chain) After(ctx context.Context, methodName string, results []interface{}, err error) {
	for _, m := range c.middlewares {
		m.After(ctx, methodName, results, err)
	}
}

type contextKey string

func (c contextKey) String() string {
	return "middleware context key " + string(c)
}
