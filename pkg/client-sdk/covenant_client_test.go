package arksdk

import (
	"testing"
	"time"

	"github.com/ark-network/ark/pkg/client-sdk/store/domain"
	"github.com/stretchr/testify/assert"
)

func TestUpdateBoardingTxsState(t *testing.T) {
	now := time.Now()

	testCases := []struct {
		description        string
		allBoardingTxs     []domain.Transaction
		oldBoardingTxs     []domain.Transaction
		expectedNewTxs     []domain.Transaction
		expectedUpdatedTxs []domain.Transaction
	}{
		{
			description:        "No boarding transactions in both lists",
			allBoardingTxs:     []domain.Transaction{},
			oldBoardingTxs:     []domain.Transaction{},
			expectedNewTxs:     []domain.Transaction{},
			expectedUpdatedTxs: []domain.Transaction{},
		},
		{
			description: "All old boarding txs are still pending and present in new list",
			allBoardingTxs: []domain.Transaction{
				{BoardingTxid: "tx1", IsPending: true, CreatedAt: now},
				{BoardingTxid: "tx2", IsPending: true, CreatedAt: now},
			},
			oldBoardingTxs: []domain.Transaction{
				{BoardingTxid: "tx1", IsPending: true, CreatedAt: now},
				{BoardingTxid: "tx2", IsPending: true, CreatedAt: now},
			},
			expectedNewTxs:     []domain.Transaction{},
			expectedUpdatedTxs: []domain.Transaction{},
		},
		{
			description: "Some old boarding txs not in new list (should be marked as pending=false)",
			allBoardingTxs: []domain.Transaction{
				{BoardingTxid: "tx1", IsPending: true, CreatedAt: now},
			},
			oldBoardingTxs: []domain.Transaction{
				{BoardingTxid: "tx1", IsPending: true, CreatedAt: now},
				{BoardingTxid: "tx2", IsPending: true, CreatedAt: now},
			},
			expectedNewTxs: []domain.Transaction{},
			expectedUpdatedTxs: []domain.Transaction{
				{BoardingTxid: "tx2", IsPending: false, CreatedAt: now},
			},
		},
		{
			description: "New boarding txs not present in old list",
			allBoardingTxs: []domain.Transaction{
				{BoardingTxid: "tx1", IsPending: true, CreatedAt: now},
				{BoardingTxid: "tx3", IsPending: true, CreatedAt: now},
			},
			oldBoardingTxs: []domain.Transaction{
				{BoardingTxid: "tx1", IsPending: true, CreatedAt: now},
			},
			expectedNewTxs: []domain.Transaction{
				{BoardingTxid: "tx3", IsPending: true, CreatedAt: now},
			},
			expectedUpdatedTxs: []domain.Transaction{},
		},
		{
			description: "No overlap between old and new boarding txs",
			allBoardingTxs: []domain.Transaction{
				{BoardingTxid: "tx3", IsPending: true, CreatedAt: now},
				{BoardingTxid: "tx4", IsPending: true, CreatedAt: now},
			},
			oldBoardingTxs: []domain.Transaction{
				{BoardingTxid: "tx1", IsPending: true, CreatedAt: now},
				{BoardingTxid: "tx2", IsPending: true, CreatedAt: now},
			},
			expectedNewTxs: []domain.Transaction{
				{BoardingTxid: "tx3", IsPending: true, CreatedAt: now},
				{BoardingTxid: "tx4", IsPending: true, CreatedAt: now},
			},
			expectedUpdatedTxs: []domain.Transaction{
				{BoardingTxid: "tx1", IsPending: false, CreatedAt: now},
				{BoardingTxid: "tx2", IsPending: false, CreatedAt: now},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			newBoardingTxs, updatedOldBoardingTxs := updateBoardingTxsState(tc.allBoardingTxs, tc.oldBoardingTxs)
			assert.Equal(t, tc.expectedNewTxs, newBoardingTxs)
			assert.Equal(t, tc.expectedUpdatedTxs, updatedOldBoardingTxs)
		})
	}
}
