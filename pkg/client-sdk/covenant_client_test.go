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
			allBoardingTxs:     nil,
			oldBoardingTxs:     nil,
			expectedNewTxs:     nil,
			expectedUpdatedTxs: nil,
		},
		{
			description: "1",
			allBoardingTxs: []domain.Transaction{
				{BoardingTxid: "tx1", IsPending: true, CreatedAt: now},
				{BoardingTxid: "tx2", IsPending: true, CreatedAt: now},
			},
			oldBoardingTxs: []domain.Transaction{
				{BoardingTxid: "tx1", IsPending: true, CreatedAt: now},
				{BoardingTxid: "tx2", IsPending: true, CreatedAt: now},
			},
			expectedNewTxs:     nil,
			expectedUpdatedTxs: nil,
		},
		{
			description: "2",
			allBoardingTxs: []domain.Transaction{
				{BoardingTxid: "tx1", IsPending: false, CreatedAt: now},
				{BoardingTxid: "tx2", IsPending: true, CreatedAt: now},
			},
			oldBoardingTxs: []domain.Transaction{
				{BoardingTxid: "tx1", IsPending: true, CreatedAt: now},
			},
			expectedNewTxs: []domain.Transaction{
				{BoardingTxid: "tx2", IsPending: true, CreatedAt: now},
			},
			expectedUpdatedTxs: []domain.Transaction{
				{BoardingTxid: "tx1", IsPending: false, CreatedAt: now},
			},
		},
		{
			description: "3",
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
			expectedUpdatedTxs: nil,
		},
		{
			description: "4",
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
			expectedUpdatedTxs: nil,
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
