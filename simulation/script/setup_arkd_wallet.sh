#!/bin/bash
set -e

cd ../server/cmd/

sleep 2

echo "Creating wallet..."
go run ./arkd wallet create --password pass

echo "Unlocking wallet..."
go run ./arkd wallet unlock --password pass

echo "Sleep for 10 seconds..."
sleep 10

echo "Get Address..."
ADDRESS=$(go run ./arkd --no-macaroon wallet address)
echo "Address: $ADDRESS"

echo "Faucet addres..."
for i in {1..5}
do
  nigiri faucet $ADDRESS
  if [ $? -ne 0 ]; then
    echo "Failed to fund wallet on attempt $i"
    exit 1
  fi
done

nigiri rpc generatetoaddress 1 bcrt1physncruhw7suslepemn3qxdnjljm9x4qus67cjnk3s8dwr8mfpcqsuj5rr

sleep 5

echo "Wallet setup complete"