# Go BLS12-381

# Example

```Go
package main

import (
	"log"

	bip39 "github.com/viwet/GoBIP39"
	"github.com/viwet/GoBIP39/words"
	bls12381 "github.com/viwet/GoBLS12381"
)

const (
    Mnemonic = "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あおぞら"
    Password = "password"
)

func main() {
	mnemonic := bip39.SplitMnemonic(Mnemonic)

	seed, err := bip39.ExtractSeed(mnemonic, words.Japanese, Password)
	if err != nil {
		log.Fatal(err)
	}

	signingKeyPath := bls12381.SigningKeyPath(42)
	withdrawalKeyPath := bls12381.WithdrawalKeyPath(42)

	signingKey, err := bls12381.DeriveKey(seed, signingKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	withdrawalKey, err := bls12381.DeriveKey(seed, withdrawalKeyPath)
	if err != nil {
		log.Fatal(err)
	}

    ...
}
```
