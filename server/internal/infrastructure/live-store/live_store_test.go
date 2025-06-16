package livestore_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	inmemory "github.com/ark-network/ark/server/internal/infrastructure/live-store/inmemory"
	redislivestore "github.com/ark-network/ark/server/internal/infrastructure/live-store/redis"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/redis/go-redis/v9"

	"github.com/stretchr/testify/require"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"

	"github.com/stretchr/testify/mock"
)

var (
	connectorsJSON = `[[{"Txid":"b4f79f5c8b27c6fb08ffe57c3eabdd4d77d6cd21e099bee890877949ac3b3c21","Tx":"cHNidP8BAOwDAAAAAcXuArkhSrxO59ox0sKDFr0zZzeJuIImgzIGH5oiKx63AQAAAAD/////BU0BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhFNAQAAAAAAACJRIIuBxfGXLJBxAcCzUNERqM25pggGv/bwyR8wuLMXmQ4RTQEAAAAAAAAiUSCLgcXxlyyQcQHAs1DREajNuaYIBr/28MkfMLizF5kOEU0BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAAAAAAAAAARRAk5zAAAAAAAMY29zaWduZXIAAAAAIQKLgcXxlyyQcQHAs1DREajNuaYIBr/28MkfMLizF5kOEQAAAAAAAA==","ParentTxid":"b71e2b229a1f0632832682b889376733bd1683c2d231dae74ebc4a21b902eec5","Leaf":false,"Level":0,"LevelIndex":0}],[{"Txid":"5e1eae3436fa3175eb238b3cc22cfccd17ec32c8f6cfd911e03f58f83b05fd7b","Tx":"cHNidP8BAGsDAAAAASE8O6xJeYeQ6L6Z4CHN1ndN3as+fOX/CPvGJ4tcn/e0AAAAAAD/////Ak0BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAAAAAAAAAARRAk5zAAAAAAAMY29zaWduZXIAAAAAIQKLgcXxlyyQcQHAs1DREajNuaYIBr/28MkfMLizF5kOEQAAAA==","ParentTxid":"b4f79f5c8b27c6fb08ffe57c3eabdd4d77d6cd21e099bee890877949ac3b3c21","Leaf":true,"Level":1,"LevelIndex":0},{"Txid":"8c8c00c0b0966880a8e9dacd8e266f3ddf938e817c7bd40295bddc5e45d900ea","Tx":"cHNidP8BAGsDAAAAASE8O6xJeYeQ6L6Z4CHN1ndN3as+fOX/CPvGJ4tcn/e0AQAAAAD/////Ak0BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAAAAAAAAAARRAk5zAAAAAAAMY29zaWduZXIAAAAAIQKLgcXxlyyQcQHAs1DREajNuaYIBr/28MkfMLizF5kOEQAAAA==","ParentTxid":"b4f79f5c8b27c6fb08ffe57c3eabdd4d77d6cd21e099bee890877949ac3b3c21","Leaf":true,"Level":1,"LevelIndex":1},{"Txid":"584408db5ed86cd5c51e2f6f027fa40a6584c3c91b8103d45ae36bc55d8a7329","Tx":"cHNidP8BAGsDAAAAASE8O6xJeYeQ6L6Z4CHN1ndN3as+fOX/CPvGJ4tcn/e0AgAAAAD/////Ak0BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAAAAAAAAAARRAk5zAAAAAAAMY29zaWduZXIAAAAAIQKLgcXxlyyQcQHAs1DREajNuaYIBr/28MkfMLizF5kOEQAAAA==","ParentTxid":"b4f79f5c8b27c6fb08ffe57c3eabdd4d77d6cd21e099bee890877949ac3b3c21","Leaf":true,"Level":1,"LevelIndex":2},{"Txid":"cbeecbaa2cd83534762c7720b29ad8e4fd9bca7e6d1a26a41a2fe0f48ef7bd6f","Tx":"cHNidP8BAGsDAAAAASE8O6xJeYeQ6L6Z4CHN1ndN3as+fOX/CPvGJ4tcn/e0AwAAAAD/////Ak0BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAAAAAAAAAARRAk5zAAAAAAAMY29zaWduZXIAAAAAIQKLgcXxlyyQcQHAs1DREajNuaYIBr/28MkfMLizF5kOEQAAAA==","ParentTxid":"b4f79f5c8b27c6fb08ffe57c3eabdd4d77d6cd21e099bee890877949ac3b3c21","Leaf":true,"Level":1,"LevelIndex":3}]]`
	requestsJSON   = `[{"Id":"d4d1735d-05d1-493c-ac3a-b0bb634a50fe","Inputs":[{"Txid":"79e74bf97b34450d69780778522087504e5340dd71c7454b017c01e3d3bfb8ab","VOut":0,"Amount":5000,"PubKey":"7086d72a8ddacc9e6e0451d92133ef583d6748a4726b632a94f26df8c802ac24","CommitmentTxid":"2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96","SpentBy":"","Spent":false,"Redeemed":false,"Swept":false,"ExpireAt":199,"RedeemTx":"cHNidP8BAJYDAAAAAeB4gUdsoDHu7o2F4IkLICEbEt0y9MejPi5mWzdZtxBBAAAAAAD/////A4gTAAAAAAAAIlEgcIbXKo3azJ5uBFHZITPvWD1nSKRya2MqlPJt+MgCrCR4zfUFAAAAACJRIHWUyazZlsz2Z0MXabtLI4spqe0ytz85GFwSHPdwqgpjAAAAAAAAAAAEUQJOcwAAAAAAAQErAOH1BQAAAAAiUSDTwlo9WBKfqLWlkkznHmITfQzQEU37+YWWyqn5B2dyGEEU+oyaCbRsXuhY4jloSwu3Ipx9OPH8BbPj7wTd/21OWk4MjR6TYePp/0T4p433ieP80aFTXXPgoCOHPjELdrL+AUDpuqwgR4YEuiemShPyiNdDm0AX1aj0sm1E5JUWApXGIahSpPpWhImz2GlO+PMJHdVNXEKXoDePj91v6H6PK1a0QRQ2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PIwyNHpNh4+n/RPinjfeJ4/zRoVNdc+CgI4c+MQt2sv4BQInUzArzkE6X+bP/eCF7F1PzaedGuM4wtX5roc9fOZ1Ja0XTErh5GUWMdZUGaqIDBlbggnPZjidgCFpV1DlEry5CFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wOlm8s7rZPsauycdJTy6UH8o1nvcz68gOYxt8V80njVkRSD6jJoJtGxe6FjiOWhLC7cinH048fwFs+PvBN3/bU5aTq0gNpbnSfElNH2C8sChc6YKbvoRfa7GVMqk94wXlMj9DyOswAd0YXB0cmVlcwIBwCgDAgBAsnUgNpbnSfElNH2C8sChc6YKbvoRfa7GVMqk94wXlMj9DyOsAcBEIPqMmgm0bF7oWOI5aEsLtyKcfTjx/AWz4+8E3f9tTlpOrSA2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PI6wAAAAA","CreatedAt":1749818677},{"Txid":"c4ae17ae1d95ec2a6adf07166e8daddee3b0f345fb1981f4af5a866517e2d198","VOut":1,"Amount":99997000,"PubKey":"7086d72a8ddacc9e6e0451d92133ef583d6748a4726b632a94f26df8c802ac24","CommitmentTxid":"2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96","SpentBy":"","Spent":false,"Redeemed":false,"Swept":false,"ExpireAt":199,"RedeemTx":"cHNidP8BAJYDAAAAAcG9HixSrAyc0eR5RX9bROesVhZhdyLYL4LBaW3H1VTNAAAAAAD/////A7gLAAAAAAAAIlEgdZTJrNmWzPZnQxdpu0sjiymp7TK3PzkYXBIc93CqCmNI1fUFAAAAACJRIHCG1yqN2syebgRR2SEz71g9Z0ikcmtjKpTybfjIAqwkAAAAAAAAAAAEUQJOcwAAAAAAAQErAOH1BQAAAAAiUSAvdzD6UGPXDhrHCF8rUw/HxzapIXAVtcA1RfCd7o2PjkEULyriza1giT7HPFxEqbI6St3+hZuq8XVP4ZPaJ/Mep1SL45HbEaCf+ZMY3cfCc6bLe13jWNIJgi8nTS2+Lw+zIUAoGS3vWUXY5YQDGNWvcCdiNIwqk3EBbF6TtEL8BCRgn54RoNRaYZg8/FoGiel49y6YpstsE5Mgv8HODEckmU7/QRQ2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PI4vjkdsRoJ/5kxjdx8Jzpst7XeNY0gmCLydNLb4vD7MhQHN+KA+97MsG3EjvOHAkTYOk6O1kB5uJv/H3IgkWUHsfx1PaulHyu1ccsguJ7Atj7ofw2aALOQ/35ACjGQF60ZRCFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wOlm8s7rZPsauycdJTy6UH8o1nvcz68gOYxt8V80njVkRSAvKuLNrWCJPsc8XESpsjpK3f6Fm6rxdU/hk9on8x6nVK0gNpbnSfElNH2C8sChc6YKbvoRfa7GVMqk94wXlMj9DyOswAd0YXB0cmVlcwIBwCgDAgBAsnUgNpbnSfElNH2C8sChc6YKbvoRfa7GVMqk94wXlMj9DyOsAcBEIC8q4s2tYIk+xzxcRKmyOkrd/oWbqvF1T+GT2ifzHqdUrSA2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PI6wAAAAA","CreatedAt":1749818677}],"Receivers":[{"Amount":100002000,"OnchainAddress":"","PubKey":"7086d72a8ddacc9e6e0451d92133ef583d6748a4726b632a94f26df8c802ac24"}]},{"Id":"6eef6c69-179c-4fe8-b183-e79637838255","Inputs":[{"Txid":"79e74bf97b34450d69780778522087504e5340dd71c7454b017c01e3d3bfb8ab","VOut":1,"Amount":99995000,"PubKey":"7594c9acd996ccf667431769bb4b238b29a9ed32b73f39185c121cf770aa0a63","CommitmentTxid":"2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96","SpentBy":"","Spent":false,"Redeemed":false,"Swept":false,"ExpireAt":199,"RedeemTx":"cHNidP8BAJYDAAAAAeB4gUdsoDHu7o2F4IkLICEbEt0y9MejPi5mWzdZtxBBAAAAAAD/////A4gTAAAAAAAAIlEgcIbXKo3azJ5uBFHZITPvWD1nSKRya2MqlPJt+MgCrCR4zfUFAAAAACJRIHWUyazZlsz2Z0MXabtLI4spqe0ytz85GFwSHPdwqgpjAAAAAAAAAAAEUQJOcwAAAAAAAQErAOH1BQAAAAAiUSDTwlo9WBKfqLWlkkznHmITfQzQEU37+YWWyqn5B2dyGEEU+oyaCbRsXuhY4jloSwu3Ipx9OPH8BbPj7wTd/21OWk4MjR6TYePp/0T4p433ieP80aFTXXPgoCOHPjELdrL+AUDpuqwgR4YEuiemShPyiNdDm0AX1aj0sm1E5JUWApXGIahSpPpWhImz2GlO+PMJHdVNXEKXoDePj91v6H6PK1a0QRQ2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PIwyNHpNh4+n/RPinjfeJ4/zRoVNdc+CgI4c+MQt2sv4BQInUzArzkE6X+bP/eCF7F1PzaedGuM4wtX5roc9fOZ1Ja0XTErh5GUWMdZUGaqIDBlbggnPZjidgCFpV1DlEry5CFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wOlm8s7rZPsauycdJTy6UH8o1nvcz68gOYxt8V80njVkRSD6jJoJtGxe6FjiOWhLC7cinH048fwFs+PvBN3/bU5aTq0gNpbnSfElNH2C8sChc6YKbvoRfa7GVMqk94wXlMj9DyOswAd0YXB0cmVlcwIBwCgDAgBAsnUgNpbnSfElNH2C8sChc6YKbvoRfa7GVMqk94wXlMj9DyOsAcBEIPqMmgm0bF7oWOI5aEsLtyKcfTjx/AWz4+8E3f9tTlpOrSA2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PI6wAAAAA","CreatedAt":1749818677},{"Txid":"c4ae17ae1d95ec2a6adf07166e8daddee3b0f345fb1981f4af5a866517e2d198","VOut":0,"Amount":3000,"PubKey":"7594c9acd996ccf667431769bb4b238b29a9ed32b73f39185c121cf770aa0a63","CommitmentTxid":"2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96","SpentBy":"","Spent":false,"Redeemed":false,"Swept":false,"ExpireAt":199,"RedeemTx":"cHNidP8BAJYDAAAAAcG9HixSrAyc0eR5RX9bROesVhZhdyLYL4LBaW3H1VTNAAAAAAD/////A7gLAAAAAAAAIlEgdZTJrNmWzPZnQxdpu0sjiymp7TK3PzkYXBIc93CqCmNI1fUFAAAAACJRIHCG1yqN2syebgRR2SEz71g9Z0ikcmtjKpTybfjIAqwkAAAAAAAAAAAEUQJOcwAAAAAAAQErAOH1BQAAAAAiUSAvdzD6UGPXDhrHCF8rUw/HxzapIXAVtcA1RfCd7o2PjkEULyriza1giT7HPFxEqbI6St3+hZuq8XVP4ZPaJ/Mep1SL45HbEaCf+ZMY3cfCc6bLe13jWNIJgi8nTS2+Lw+zIUAoGS3vWUXY5YQDGNWvcCdiNIwqk3EBbF6TtEL8BCRgn54RoNRaYZg8/FoGiel49y6YpstsE5Mgv8HODEckmU7/QRQ2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PI4vjkdsRoJ/5kxjdx8Jzpst7XeNY0gmCLydNLb4vD7MhQHN+KA+97MsG3EjvOHAkTYOk6O1kB5uJv/H3IgkWUHsfx1PaulHyu1ccsguJ7Atj7ofw2aALOQ/35ACjGQF60ZRCFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wOlm8s7rZPsauycdJTy6UH8o1nvcz68gOYxt8V80njVkRSAvKuLNrWCJPsc8XESpsjpK3f6Fm6rxdU/hk9on8x6nVK0gNpbnSfElNH2C8sChc6YKbvoRfa7GVMqk94wXlMj9DyOswAd0YXB0cmVlcwIBwCgDAgBAsnUgNpbnSfElNH2C8sChc6YKbvoRfa7GVMqk94wXlMj9DyOsAcBEIC8q4s2tYIk+xzxcRKmyOkrd/oWbqvF1T+GT2ifzHqdUrSA2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PI6wAAAAA","CreatedAt":1749818677}],"Receivers":[{"Amount":99998000,"OnchainAddress":"","PubKey":"7594c9acd996ccf667431769bb4b238b29a9ed32b73f39185c121cf770aa0a63"}]}]`
	tx1            = "cHNidP8BAIgDAAAAAnv9BTv4WD/gEdnP9sgy7BfN/CzCPIsj63Ux+jY0rh5eAAAAAAD/////q7i/0+MBfAFLRcdx3UBTTlCHIFJ4B3hpDUU0e/lL53kAAAAAAP////8C1RQAAAAAAAAWABQrwBxZxFNQ+DSDSqacn20LIQKLrQAAAAAAAAAABFECTnMAAAAAAAEBK00BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAQEriBMAAAAAAAAiUSBwhtcqjdrMnm4EUdkhM+9YPWdIpHJrYyqU8m34yAKsJEEULyriza1giT7HPFxEqbI6St3+hZuq8XVP4ZPaJ/Mep1SL45HbEaCf+ZMY3cfCc6bLe13jWNIJgi8nTS2+Lw+zIUAMWsyNnOkGuXqv1tZryHrR2opcv1IE8y8vd0plIWjcBzC75lIIeMaV3QLOicJkpx854Hpb4hdGylSRnw9wTDBjQhXBUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsDAx+14WC2NF93SA39AJr+zuMBDbBkzxBXNHpuv/6Dnb0UgLyriza1giT7HPFxEqbI6St3+hZuq8XVP4ZPaJ/Mep1StIDaW50nxJTR9gvLAoXOmCm76EX2uxlTKpPeMF5TI/Q8jrMAAAAA="
	tx2            = "cHNidP8BAIgDAAAAAm+994704C8apCYabX7Km/3k2JqyIHcsdjQ12Cyqy+7LAAAAAAD/////mNHiF2WGWq/0gRn7RfOw496tjW4WB99qKuyVHa4XrsQBAAAAAP////8Cldb1BQAAAAAWABQrwBxZxFNQ+DSDSqacn20LIQKLrQAAAAAAAAAABFECTnMAAAAAAAEBK00BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAQErSNX1BQAAAAAiUSBwhtcqjdrMnm4EUdkhM+9YPWdIpHJrYyqU8m34yAKsJEEULyriza1giT7HPFxEqbI6St3+hZuq8XVP4ZPaJ/Mep1SL45HbEaCf+ZMY3cfCc6bLe13jWNIJgi8nTS2+Lw+zIUASzdEkMZS1M3JBzp2N/ky+nki8GRJ5WpQY/7UZLI8AuFe0+26NmFuwbCdABpfu0vbRcwgKOS+9B3Fot0jlBLP5QhXBUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsDAx+14WC2NF93SA39AJr+zuMBDbBkzxBXNHpuv/6Dnb0UgLyriza1giT7HPFxEqbI6St3+hZuq8XVP4ZPaJ/Mep1StIDaW50nxJTR9gvLAoXOmCm76EX2uxlTKpPeMF5TI/Q8jrMAAAAA="
	tx3            = "cHNidP8BAIgDAAAAAuoA2UVe3L2VAtR7fIGOk989byaOzdrpqIBolrDAAIyMAAAAAAD/////q7i/0+MBfAFLRcdx3UBTTlCHIFJ4B3hpDUU0e/lL53kBAAAAAP////8Cxc71BQAAAAAWABQrwBxZxFNQ+DSDSqacn20LIQKLrQAAAAAAAAAABFECTnMAAAAAAAEBK00BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAQEreM31BQAAAAAiUSB1lMms2ZbM9mdDF2m7SyOLKantMrc/ORhcEhz3cKoKY0EU+oyaCbRsXuhY4jloSwu3Ipx9OPH8BbPj7wTd/21OWk4MjR6TYePp/0T4p433ieP80aFTXXPgoCOHPjELdrL+AUDEYB0aGjMx9DiXleloNHVh6aSGUegpjAsfFfICVFEPuGCDnugSnlF3xZyM9RfqeVlkftA4oJ9peymWG4FvpD8xQhXAUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsB2DIZg1WVGJ8awnZ7cvgzISiU5sOtGQ6kz8wgGr4zeREUg+oyaCbRsXuhY4jloSwu3Ipx9OPH8BbPj7wTd/21OWk6tIDaW50nxJTR9gvLAoXOmCm76EX2uxlTKpPeMF5TI/Q8jrMAAAAA="
	tx4            = "cHNidP8BAIgDAAAAAilzil3Fa+Na1AOBG8nDhGUKpH8Cby8exdVs2F7bCERYAAAAAAD/////mNHiF2WGWq/0gRn7RfOw496tjW4WB99qKuyVHa4XrsQAAAAAAP////8CBQ0AAAAAAAAWABQrwBxZxFNQ+DSDSqacn20LIQKLrQAAAAAAAAAABFECTnMAAAAAAAEBK00BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAQEruAsAAAAAAAAiUSB1lMms2ZbM9mdDF2m7SyOLKantMrc/"

	txReqFixture1 = `{"boardingInputs":[{"Txid":"1e1448b9f2c44e4bc861db45864097d94fa7519dab9cba12c886a0c244932145","VOut":1,"Tapscripts":["039d0440b27520fa8c9a09b46c5ee858e239684b0bb7229c7d38f1fc05b3e3ef04ddff6d4e5a4eac","20fa8c9a09b46c5ee858e239684b0bb7229c7d38f1fc05b3e3ef04ddff6d4e5a4ead203696e749f125347d82f2c0a173a60a6efa117daec654caa4f78c1794c8fd0f23ac"],"Amount":100000000}],"cosignerPubkeys":["039f2214798b94cd517ccd561e739ebb73cecacdc41b387beb460dda097c2b7c67"],"request":{"Id":"0222bfa8-c753-4b41-a5f9-d4e12d726413","Inputs":[{"Txid":"24de502601c21cf7b227c0667ffe1175841cdd4f6e5b20d3063387333d0b10da","VOut":0,"CommitmentTxid":"0000000000000000000000000000000000000000000000000000000000000000"}],"Receivers":[{"Amount":100000000,"OnchainAddress":"","PubKey":"7594c9acd996ccf667431769bb4b238b29a9ed32b73f39185c121cf770aa0a63"}]}}`
	txReqFixture2 = `{"boardingInputs":[{"Txid":"14de502601c21cf7b227c0667ffe1175841cdd4f6e5b20d3063387333d0b10db","VOut":1,"Tapscripts":["039d0440b275202f2ae2cdad60893ec73c5c44a9b23a4addfe859baaf1754fe193da27f31ea754ac","202f2ae2cdad60893ec73c5c44a9b23a4addfe859baaf1754fe193da27f31ea754ad203696e749f125347d82f2c0a173a60a6efa117daec654caa4f78c1794c8fd0f23ac"],"Amount":100000000}],"cosignerPubkeys":["021f5b9ff8f25ff7b8984f444abb75621267251cbba76f32d12bf6b4da3b3a7096"],"request":{"Id":"2a4d69f3-ce1b-40b3-a48d-fb61ec21b15f","Inputs":[],"Receivers":[{"Amount":100000000,"OnchainAddress":"","PubKey":"7086d72a8ddacc9e6e0451d92133ef583d6748a4726b632a94f26df8c802ac24"}]}}`

	offchainTxJSON = `{"Stage":{"Code":2,"Ended":false,"Failed":false},"StartingTimestamp":1749818677,"EndingTimestamp":0,"VirtualTxid":"79e74bf97b34450d69780778522087504e5340dd71c7454b017c01e3d3bfb8ab","VirtualTx":"cHNidP8BAJYDAAAAAeB4gUdsoDHu7o2F4IkLICEbEt0y9MejPi5mWzdZtxBBAAAAAAD/////A4gTAAAAAAAAIlEgcIbXKo3azJ5uBFHZITPvWD1nSKRya2MqlPJt+MgCrCR4zfUFAAAAACJRIHWUyazZlsz2Z0MXabtLI4spqe0ytz85GFwSHPdwqgpjAAAAAAAAAAAEUQJOcwAAAAAAAQErAOH1BQAAAAAiUSDTwlo9WBKfqLWlkkznHmITfQzQEU37+YWWyqn5B2dyGEEU+oyaCbRsXuhY4jloSwu3Ipx9OPH8BbPj7wTd/21OWk4MjR6TYePp/0T4p433ieP80aFTXXPgoCOHPjELdrL+AUDpuqwgR4YEuiemShPyiNdDm0AX1aj0sm1E5JUWApXGIahSpPpWhImz2GlO+PMJHdVNXEKXoDePj91v6H6PK1a0QRQ2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PIwyNHpNh4+n/RPinjfeJ4/zRoVNdc+CgI4c+MQt2sv4BQInUzArzkE6X+bP/eCF7F1PzaedGuM4wtX5roc9fOZ1Ja0XTErh5GUWMdZUGaqIDBlbggnPZjidgCFpV1DlEry5CFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wOlm8s7rZPsauycdJTy6UH8o1nvcz68gOYxt8V80njVkRSD6jJoJtGxe6FjiOWhLC7cinH048fwFs+PvBN3/bU5aTq0gNpbnSfElNH2C8sChc6YKbvoRfa7GVMqk94wXlMj9DyOswAd0YXB0cmVlcwIBwCgDAgBAsnUgNpbnSfElNH2C8sChc6YKbvoRfa7GVMqk94wXlMj9DyOsAcBEIPqMmgm0bF7oWOI5aEsLtyKcfTjx/AWz4+8E3f9tTlpOrSA2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PI6wAAAAA","CheckpointTxs":{"4110b759375b662e3ea3c7f432dd121b21200b89e0858deeee31a06c478178e0":"cHNidP8BAGsDAAAAARrFJ/P3vwEZY75OHSqgWMz3RaeIrDt7pxWqEAXZwfz+AAAAAAD/////AgDh9QUAAAAAIlEg08JaPVgSn6i1pZJM5x5iE30M0BFN+/mFlsqp+QdnchgAAAAAAAAAAARRAk5zAAAAAAABASsA4fUFAAAAACJRIHWUyazZlsz2Z0MXabtLI4spqe0ytz85GFwSHPdwqgpjQRQ2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PIwyNHpNh4+n/RPinjfeJ4/zRoVNdc+CgI4c+MQt2sv4BQCgwEdt3LF/ub7J1hnF3+kbMvbo0Wqt3VpGDsto8wiqy6KL6zHMxKYEZAn1z3SLCo7wKZFsWk1gdx65rINE5JM5CFcBQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wHYMhmDVZUYnxrCdnty+DMhKJTmw60ZDqTPzCAavjN5ERSD6jJoJtGxe6FjiOWhLC7cinH048fwFs+PvBN3/bU5aTq0gNpbnSfElNH2C8sChc6YKbvoRfa7GVMqk94wXlMj9DyOswAd0YXB0cmVlcwIBwCgDAgBAsnUg+oyaCbRsXuhY4jloSwu3Ipx9OPH8BbPj7wTd/21OWk6sAcBEIPqMmgm0bF7oWOI5aEsLtyKcfTjx/AWz4+8E3f9tTlpOrSA2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PI6wAAAA="},"CommitmentTxids":{"4110b759375b662e3ea3c7f432dd121b21200b89e0858deeee31a06c478178e0":"2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96"},"RootCommitmentTxId":"2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96","ExpiryTimestamp":199,"FailReason":"","Version":0}`

	h1 = sha256.Sum256([]byte("fdbc502adf42a40dc7c0b2d3b50b9c0b01f9c386dc9bef5233bc9f39acdf48ae"))
	h2 = sha256.Sum256([]byte("340f30bc56d8de1364120aaf8734f684a28084bc9fbb17029584378d1422beff"))

	roundId           = "218767a7-bceb-4f79-90e7-ad07ddccf246"
	uniqueSignersJSON = `{"021f5b9ff8f25ff7b8984f444abb75621267251cbba76f32d12bf6b4da3b3a7096":{},"039f2214798b94cd517ccd561e739ebb73cecacdc41b387beb460dda097c2b7c67":{}}`

	n1 = `[[{"PubNonce":[2,5,82,234,130,67,17,58,12,243,167,3,105,241,202,120,93,160,99,2,38,138,156,171,183,210,8,64,101,250,207,43,137,3,103,79,233,244,21,91,194,216,196,238,124,126,9,137,220,122,74,77,58,104,15,53,46,208,93,16,145,24,134,124,70,193]}],[{"PubNonce":[2,30,11,219,123,243,214,33,245,158,36,140,146,227,107,167,14,90,212,7,96,37,144,168,99,195,185,226,217,41,228,9,227,3,53,165,228,54,162,38,213,158,72,232,108,251,82,31,62,249,70,175,24,155,120,68,183,227,165,83,229,135,80,104,14,237]},null]]`
	n2 = `[[{"PubNonce":[3,72,158,32,4,32,249,174,27,185,103,49,207,109,78,205,172,105,77,129,108,186,187,218,166,113,172,71,134,249,231,156,100,3,249,54,28,22,160,173,112,30,176,238,129,77,157,82,146,140,177,98,79,56,195,179,232,159,163,90,205,184,207,163,214,228]}],[null,{"PubNonce":[3,112,126,254,35,188,151,241,121,105,165,209,140,13,223,114,35,243,141,171,75,4,61,190,86,152,169,229,181,220,112,155,227,2,38,39,65,76,140,3,106,175,198,131,186,0,163,67,91,17,251,107,218,187,74,88,32,46,113,199,178,47,136,216,233,137]}]]`

	s1 = "02000000010000000192f4f3d38d66bbe5decf37d423e9c58cc012c1b0f8a86ef1c8ca6e84bf4d4058020000000001faf56059605dba5ee645c62798468a69b825346eeafcdeb95dbffb8c7604d466"
	s2 = "020000000100000001d60abaf87393522bcf6d0db90df58b9f93e3db5fdf55b1daeade1e1aba786d6f0200000001e75120ecbd4e2b51f4db7cea04c8df46ffd370a2e622627b6a0f73a2332329c800"

	validTx = map[domain.VtxoKey]string{
		domain.VtxoKey{Txid: "79e74bf97b34450d69780778522087504e5340dd71c7454b017c01e3d3bfb8ab", VOut: 0}: "tx1",
		domain.VtxoKey{Txid: "c4ae17ae1d95ec2a6adf07166e8daddee3b0f345fb1981f4af5a866517e2d198", VOut: 1}: "tx2",
		domain.VtxoKey{Txid: "79e74bf97b34450d69780778522087504e5340dd71c7454b017c01e3d3bfb8ab", VOut: 1}: "tx2",
		domain.VtxoKey{Txid: "c4ae17ae1d95ec2a6adf07166e8daddee3b0f345fb1981f4af5a866517e2d198", VOut: 0}: "tx2",
	}
)

func TestLiveStoreImplementations(t *testing.T) {
	redisOpts, err := redis.ParseURL("redis://localhost:6379/0")
	require.NoError(t, err)
	rdb := redis.NewClient(redisOpts)

	txBuilder := new(mockedTxBuilder)
	txBuilder.On("VerifyForfeitTxs", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(validTx, nil)

	stores := []struct {
		name  string
		store ports.LiveStore
	}{
		{"inmemory", inmemory.NewLiveStore(txBuilder)},
		{"redis", redislivestore.NewLiveStore(rdb, txBuilder, 5)},
	}

	for _, tt := range stores {
		t.Run(tt.name, func(t *testing.T) {
			runLiveStoreTests(t, tt.store)
		})
	}
}

func runLiveStoreTests(t *testing.T, store ports.LiveStore) {
	t.Run("TxRequestsStore", func(t *testing.T) {
		req1, err := parseTxRequestsFixtures(txReqFixture1)
		require.NoError(t, err)
		req2, err := parseTxRequestsFixtures(txReqFixture2)
		require.NoError(t, err)

		// Push
		err = store.TxRequests().Push(req1.Request, req1.BoardingInputs, req1.CosignersPublicKeys)
		require.NoError(t, err)
		err = store.TxRequests().Push(req2.Request, req2.BoardingInputs, req2.CosignersPublicKeys)
		require.NoError(t, err)

		// View
		got, ok := store.TxRequests().View(req1.Request.Id)
		require.True(t, ok)
		require.Equal(t, req1.Request.Id, got.Id)
		_, ok = store.TxRequests().View("nonexistent")
		require.False(t, ok)

		// ViewAll
		all, err := store.TxRequests().ViewAll([]string{req1.Request.Id, req2.Request.Id, "nonexistent"})
		require.NoError(t, err)
		foundIds := map[string]bool{req1.Request.Id: false, req2.Request.Id: false}
		for _, r := range all {
			foundIds[r.Id] = true
		}
		for id := range foundIds {
			require.True(t, foundIds[id])
		}

		// IncludesAny
		found, _ := store.TxRequests().IncludesAny([]domain.VtxoKey{})
		require.False(t, found)

		found, _ = store.TxRequests().IncludesAny([]domain.VtxoKey{{Txid: "24de502601c21cf7b227c0667ffe1175841cdd4f6e5b20d3063387333d0b10da", VOut: 0}})
		require.True(t, found)

		// Len
		ln := store.TxRequests().Len()
		require.True(t, ln == 2)

		// Pop
		popped := store.TxRequests().Pop(1)
		if len(popped) > 1 {
			t.Errorf("Pop returned more than requested")
		}
		_ = store.TxRequests().Pop(100)

		// Delete
		require.NoError(t, store.TxRequests().Delete([]string{req2.Request.Id}))

		// Delete non-existent
		require.NoError(t, store.TxRequests().Delete([]string{"doesnotexist"}))

		// DeleteAll
		require.NoError(t, store.TxRequests().DeleteAll())

		// DeleteVtxos
		store.TxRequests().DeleteVtxos()
	})

	t.Run("ForfeitTxsStore", func(t *testing.T) {
		connectors, requests, err := parseForfeitTxsFixture(connectorsJSON, requestsJSON)
		require.NoError(t, err)

		// Init
		err = store.ForfeitTxs().Init(connectors, requests)
		require.NoError(t, err)

		// Sign
		err = store.ForfeitTxs().Sign([]string{tx1, tx2, tx3, tx4})
		require.NoError(t, err)

		// AllSigned
		require.True(t, store.ForfeitTxs().AllSigned())

		require.True(t, store.ForfeitTxs().Len() == 4)

		forfeits, err := store.ForfeitTxs().Pop()
		require.NoError(t, err)
		require.Equal(t, 4, len(forfeits))

		// Len
		require.True(t, store.ForfeitTxs().Len() == 0)

		store.ForfeitTxs().Reset()

		require.Equal(t, 0, store.ForfeitTxs().Len())
	})

	t.Run("OffChainTxStore", func(t *testing.T) {
		tx, err := parseOffchainTxFixture(offchainTxJSON)
		require.NoError(t, err)

		// Add
		store.OffchainTxs().Add(tx)

		// Get
		_, exists := store.OffchainTxs().Get("nonexistent")
		require.False(t, exists)

		// Get
		_, exists = store.OffchainTxs().Get(tx.VirtualTxid)
		require.True(t, exists)

		// Includes
		outpointJSON := `{"Txid":"fefcc1d90510aa15a77b3bac88a745f7cc58a02a1d4ebe631901bff7f327c51a","VOut":0}`
		var outpoint domain.VtxoKey
		err = json.Unmarshal([]byte(outpointJSON), &outpoint)
		require.NoError(t, err)
		exists = store.OffchainTxs().Includes(outpoint)
		require.True(t, exists)

		// Remove
		store.OffchainTxs().Remove(tx.VirtualTxid)

		// Get
		_, exists = store.OffchainTxs().Get(tx.VirtualTxid)
		require.False(t, exists)
	})

	t.Run("CurrentRoundStore", func(t *testing.T) {
		r := domain.NewRound()

		// Upsert
		err := store.CurrentRound().Upsert(func(_ *domain.Round) *domain.Round { return r })
		require.NoError(t, err)

		// Get
		got := store.CurrentRound().Get()
		require.Equal(t, r.Id, got.Id)

		// Fail
		events := store.CurrentRound().Fail(fmt.Errorf("fail"))
		require.Len(t, events, 1)
	})

	t.Run("ConfirmationSessionsStore", func(t *testing.T) {
		hashes := [][32]byte{h1, h2}

		// Init
		store.ConfirmationSessions().Init(hashes)

		// IsInit
		require.True(t, store.ConfirmationSessions().Initialized())

		doneCh := make(chan struct{})
		sessionCompleteCh := store.ConfirmationSessions().SessionCompleted()
		go func() {
			<-sessionCompleteCh
			doneCh <- struct{}{}
		}()

		// Confirm
		go func() {
			time.Sleep(1 * time.Second)
			err := store.ConfirmationSessions().Confirm("fdbc502adf42a40dc7c0b2d3b50b9c0b01f9c386dc9bef5233bc9f39acdf48ae")
			require.NoError(t, err)

			err = store.ConfirmationSessions().Confirm("340f30bc56d8de1364120aaf8734f684a28084bc9fbb17029584378d1422beff")
			require.NoError(t, err)
		}()

		select {
		case <-time.After(5 * time.Second):
			require.Fail(t, "Confirmation session not completed")
		case <-doneCh:
		}

		// Get
		got := store.ConfirmationSessions().Get()
		require.Equal(t, 2, len(got.IntentsHashes))
		require.Equal(t, 2, got.NumIntents)

		// Reset
		store.ConfirmationSessions().Reset()

		// IsInit
		require.False(t, store.ConfirmationSessions().Initialized())
	})

	t.Run("TreeSigningSessionsStore", func(t *testing.T) {
		// New
		var uniqueSigners map[string]struct{}
		err := json.Unmarshal([]byte(uniqueSignersJSON), &uniqueSigners)
		require.NoError(t, err)
		sigSession := store.TreeSigingSessions().New(roundId, uniqueSigners)
		require.Equal(t, 2+1, sigSession.NbCosigners)

		noncesCollectedCh := store.TreeSigingSessions().NoncesCollected(roundId)
		signaturesCollectedCh := store.TreeSigingSessions().SignaturesCollected(roundId)
		doneCh := make(chan struct{})
		go func() {
			<-noncesCollectedCh
			<-signaturesCollectedCh
			doneCh <- struct{}{}
		}()

		go func() {
			// Collect nonces
			var nonce1, nonce2 tree.TreeNonces
			err = json.Unmarshal([]byte(n1), &nonce1)
			require.NoError(t, err)
			err = json.Unmarshal([]byte(n2), &nonce2)
			require.NoError(t, err)
			err = store.TreeSigingSessions().AddNonces(context.Background(), roundId, "021f5b9ff8f25ff7b8984f444abb75621267251cbba76f32d12bf6b4da3b3a7096", nonce1)
			require.NoError(t, err)
			err = store.TreeSigingSessions().AddNonces(context.Background(), roundId, "039f2214798b94cd517ccd561e739ebb73cecacdc41b387beb460dda097c2b7c67", nonce2)
			require.NoError(t, err)

			// Collect signatures
			sig1, err := tree.DecodeSignatures(hex.NewDecoder(strings.NewReader(s1)))
			require.NoError(t, err)
			sig2, err := tree.DecodeSignatures(hex.NewDecoder(strings.NewReader(s2)))
			require.NoError(t, err)
			require.NoError(t, store.TreeSigingSessions().AddSignatures(context.Background(), roundId, "021f5b9ff8f25ff7b8984f444abb75621267251cbba76f32d12bf6b4da3b3a7096", sig1))
			require.NoError(t, store.TreeSigingSessions().AddSignatures(context.Background(), roundId, "039f2214798b94cd517ccd561e739ebb73cecacdc41b387beb460dda097c2b7c67", sig2))
		}()

		select {
		case <-time.After(5 * time.Second):
			t.Fatal("timeout")
		case <-doneCh:
		}

		// Delete
		store.TreeSigingSessions().Delete(roundId)

		// Get
		sigSession, exists := store.TreeSigingSessions().Get(roundId)
		require.False(t, exists)
		require.Nil(t, sigSession)
	})

	t.Run("BoardingInputsStore", func(t *testing.T) {
		store.BoardingInputs().Set(42)
		require.Equal(t, 42, store.BoardingInputs().Get())
		store.BoardingInputs().Set(0)
		require.Equal(t, 0, store.BoardingInputs().Get())
	})
}

type TxRequestsPushFixture struct {
	Request             domain.TxRequest      `json:"request"`
	BoardingInputs      []ports.BoardingInput `json:"boardingInputs"`
	CosignersPublicKeys []string              `json:"cosignerPubkeys"`
}

func parseTxRequestsFixtures(fixtureJSON string) (*TxRequestsPushFixture, error) {
	var fixture TxRequestsPushFixture
	if err := json.Unmarshal([]byte(fixtureJSON), &fixture); err != nil {
		return nil, err
	}
	return &fixture, nil
}

func parseForfeitTxsFixture(connectorsJSON, requestsJSON string) (tree.TxTree, []domain.TxRequest, error) {
	var connectors tree.TxTree
	if err := json.Unmarshal([]byte(connectorsJSON), &connectors); err != nil {
		return nil, nil, err
	}

	var requests []domain.TxRequest
	if err := json.Unmarshal([]byte(requestsJSON), &requests); err != nil {
		return nil, nil, err
	}

	return connectors, requests, nil
}

func parseOffchainTxFixture(txJSON string) (domain.OffchainTx, error) {
	var tx domain.OffchainTx
	if err := json.Unmarshal([]byte(txJSON), &tx); err != nil {
		return domain.OffchainTx{}, err
	}

	return tx, nil
}

type mockedTxBuilder struct {
	mock.Mock
}

func (m *mockedTxBuilder) VerifyForfeitTxs(vtxos []domain.Vtxo, connectors tree.TxTree, txs []string, connectorIndex map[string]domain.Outpoint) (valid map[domain.VtxoKey]string, err error) {
	args := m.Called(vtxos, connectors, txs, connectorIndex)
	return args.Get(0).(map[domain.VtxoKey]string), args.Error(1)
}

func (m *mockedTxBuilder) BuildRoundTx(serverPubkey *secp256k1.PublicKey, txRequests domain.TxRequests, boardingInputs []ports.BoardingInput, connectorAddresses []string, cosignerPubkeys [][]string) (roundTx string, vtxoTree tree.TxTree, connectorAddress string, connectors tree.TxTree, err error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockedTxBuilder) BuildSweepTx(inputs []ports.SweepInput) (txid string, signedSweepTx string, err error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockedTxBuilder) GetSweepInput(node tree.Node) (vtxoTreeExpiry *common.RelativeLocktime, sweepInput ports.SweepInput, err error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockedTxBuilder) FinalizeAndExtract(tx string) (txhex string, err error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockedTxBuilder) VerifyTapscriptPartialSigs(tx string) (valid bool, txid string, err error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockedTxBuilder) FindLeaves(vtxoTree tree.TxTree, fromtxid string, vout uint32) (leaves []tree.Node, err error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockedTxBuilder) VerifyAndCombinePartialTx(dest string, src string) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockedTxBuilder) CountSignedTaprootInputs(tx string) (int, error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockedTxBuilder) GetTxID(tx string) (string, error) {
	//TODO implement me
	panic("implement me")
}
