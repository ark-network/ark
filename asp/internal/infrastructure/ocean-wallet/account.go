package oceanwallet

import (
	"context"

	pb "github.com/ark-network/ark/api-spec/protobuf/gen/ocean/v1"
	"github.com/vulpemventures/go-elements/address"
)

func (s *service) DeriveAddresses(
	ctx context.Context, numOfAddresses int,
) ([]string, error) {
	res, err := s.accountClient.DeriveAddresses(ctx, &pb.DeriveAddressesRequest{
		AccountName:    accountLabel,
		NumOfAddresses: uint64(numOfAddresses),
	})
	if err != nil {
		return nil, err
	}
	// By default, ocean generates confidential addresses. Since we're going to
	// create unconfidential txs only, let's return unconf addresses.
	addresses := make([]string, 0, numOfAddresses)
	for _, addr := range res.GetAddresses() {
		info, _ := address.FromConfidential(addr)
		addresses = append(addresses, info.Address)
	}
	return addresses, nil
}
