package interfaces

import "github.com/urfave/cli/v2"

type CLI interface {
	Balance(ctx *cli.Context) error
	Init(ctx *cli.Context) error
	Receive(ctx *cli.Context) error
	Redeem(ctx *cli.Context) error
	Send(ctx *cli.Context) error
	Onboard(ctx *cli.Context) error
}
