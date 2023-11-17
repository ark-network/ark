package ports

import "context"

type WalletService interface {
	Wallet() Wallet
	Account() Account
	Transaction() Transaction
	Notification() Notification
	Close()
}

type Wallet interface {
	GenSeed(ctx context.Context) ([]string, error)
	InitWallet(ctx context.Context, mnemonic []string, password string) error
	Unlock(ctx context.Context, password string) error
	Lock(ctx context.Context, password string) error
	Status(ctx context.Context) (WalletStatus, error)
}

type Account interface {
	DeriveAddresses(ctx context.Context, num int) ([]string, error)
	GetBalance(ctx context.Context) (map[string]Balance, error)
	ListUtxos(ctx context.Context) ([]Utxo, []Utxo, error)
}

type Transaction interface {
	GetTransaction(ctx context.Context, txid string) (string, error)
	UpdatePset(
		ctx context.Context, pset string,
		ins []TxInput, outs []TxOutput,
	) (string, error)
	SignPset(
		ctx context.Context, pset string, extractRawTx bool,
	) (string, error)
	Transfer(ctx context.Context, outs []TxOutput) (string, error)
	BroadcastTransaction(ctx context.Context, txHex string) (string, error)
}

type Notification interface {
	GetTxNotifications() chan WalletTxNotification
	GetUtxoNotifications() chan WalletUtxoNotification
}

type WalletStatus interface {
	IsInitialized() bool
	IsUnlocked() bool
	IsSynced() bool
}

type WalletTxNotification interface {
	GetEventType() WalletTxEventType
	GetAccountNames() []string
	GetTxHex() string
	GetBlockDetails() BlockInfo
}

type WalletUtxoNotification interface {
	GetEventType() WalletUtxoEventType
	GetUtxos() []Utxo
}

type WalletTxEventType interface {
	IsUnconfirmed() bool
	IsConfirmed() bool
	IsBroadcasted() bool
}

type WalletUtxoEventType interface {
	IsUnconfirmed() bool
	IsConfirmed() bool
	IsLocked() bool
	IsUnlocked() bool
	IsSpent() bool
}

type Balance interface {
	GetConfirmedBalance() uint64
	GetUnconfirmedBalance() uint64
	GetLockedBalance() uint64
	GetTotalBalance() uint64
}

type UtxoKey interface {
	GetTxid() string
	GetIndex() uint32
}

type UtxoStatus interface {
	GetTxid() string
	GetBlockInfo() BlockInfo
}

type Utxo interface {
	UtxoKey
	GetAsset() string
	GetValue() uint64
	GetScript() string
	GetConfirmedStatus() UtxoStatus
	GetSpentStatus() UtxoStatus
}

type TxInput interface {
	UtxoKey
	GetScript() string
	GetScriptSigSize() int
	GetWitnessSize() int
}

type TxOutput interface {
	GetAsset() string
	GetAmount() uint64
	GetScript() string
}

type BlockInfo interface {
	GetHash() string
	GetHeight() uint64
	GetTimestamp() int64
}
