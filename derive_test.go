package gobls12381

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func Test_deriveMasterKey(t *testing.T) {
	f := func(t *testing.T, seedHex, wantedKey string) {
		seed, err := hex.DecodeString(seedHex)
		if err != nil {
			t.Fatal(err)
		}

		masterSecretKey, err := deriveMasterSecretKey(seed)
		if err != nil {
			t.Fatal(err)
		}

		if masterSecretKey.String() != wantedKey {
			t.Fatalf(
				"Invalid master key:\nWant: %s\nGot:  %s\n",
				wantedKey,
				masterSecretKey.String(),
			)
		}
	}

	var vector [][]string
	file, err := os.Open("tests/derive_master_SK.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&vector); err != nil {
		t.Fatal(err)
	}

	for _, v := range vector {
		seed, key := v[0], v[1]
		f(t, seed, key)
	}
}
