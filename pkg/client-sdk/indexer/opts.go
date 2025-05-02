package indexer

import "time"

type RequestOption struct {
	page *PageRequest
}

func (o *RequestOption) WithPage(page *PageRequest) {
	o.page = page
}

func (o *RequestOption) GetPage() *PageRequest {
	return o.page
}

type GetVtxosRequestOption struct {
	RequestOption
	spentOnly     bool
	spendableOnly bool
}

func (o *GetVtxosRequestOption) WithSpentOnly(spentOnly bool) {
	o.spentOnly = spentOnly
}

func (o *GetVtxosRequestOption) GetSpentOnly() bool {
	return o.spentOnly
}

func (o *GetVtxosRequestOption) WithSpendableOnly(spendableOnly bool) {
	o.spendableOnly = spendableOnly
}

func (o *GetVtxosRequestOption) GetSpendableOnly() bool {
	return o.spendableOnly
}

type GetTxHistoryRequestOption struct {
	RequestOption
	startTime time.Time
	endTime   time.Time
}

func (o *GetTxHistoryRequestOption) WithStartTime(startTime time.Time) {
	o.startTime = startTime
}

func (o *GetTxHistoryRequestOption) GetStartTime() time.Time {
	return o.startTime
}

func (o *GetTxHistoryRequestOption) WithEndTime(endTime time.Time) {
	o.endTime = endTime
}

func (o *GetTxHistoryRequestOption) GetEndTime() time.Time {
	return o.endTime
}
