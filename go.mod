module github.com/ark-network/ark

go 1.21.0

replace github.com/ark-network/ark/common => ./pkg/common

require github.com/sirupsen/logrus v1.9.3

require (
	github.com/stretchr/testify v1.8.0 // indirect
	golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8 // indirect
)
