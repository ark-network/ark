package ports

type SweeperService interface {
	Start() error
	Stop() error
}
