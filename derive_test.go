package gobls12381

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strings"
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

	var vector []struct {
		Seed     string `json:"seed"`
		MasterSK string `json:"master_SK"`
	}
	file, err := os.Open("tests/derive_master_SK.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&vector); err != nil {
		t.Fatal(err)
	}

	for _, v := range vector {
		f(t, v.Seed, v.MasterSK)
	}
}

func Test_deriveLamport0(t *testing.T) {
	f := func(t *testing.T, seedHex string, index uint32, wantedLamport []string) {
		seed, err := hex.DecodeString(seedHex)
		if err != nil {
			t.Fatal(err)
		}

		masterSecretKey, err := deriveMasterSecretKey(seed)
		if err != nil {
			t.Fatal(err)
		}

		salt := make([]byte, 4)
		binary.BigEndian.PutUint32(salt, index)

		lamport0, err := deriveLamport0(masterSecretKey, salt)
		if err != nil {
			t.Fatal(err)
		}

		if slices.CompareFunc(
			lamport0,
			wantedLamport,
			func(a []byte, b string) int { return strings.Compare(hex.EncodeToString(a), b) },
		) != 0 {
			t.Fatal("Invalid lamport0 calculation")
		}
	}

	var test struct {
		Seed     string   `json:"seed"`
		Index    uint32   `json:"index"`
		Lamport0 []string `json:"lamport_0"`
	}

	file, err := os.Open("tests/derive_lamport_0.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&test); err != nil {
		t.Fatal(err)
	}

	f(t, test.Seed, test.Index, test.Lamport0)
}

func Test_deriveLamport1(t *testing.T) {
	f := func(t *testing.T, seedHex string, index uint32, wantedLamport []string) {
		seed, err := hex.DecodeString(seedHex)
		if err != nil {
			t.Fatal(err)
		}

		masterSecretKey, err := deriveMasterSecretKey(seed)
		if err != nil {
			t.Fatal(err)
		}

		salt := make([]byte, 4)
		binary.BigEndian.PutUint32(salt, index)

		lamport1, err := deriveLamport1(masterSecretKey, salt)
		if err != nil {
			t.Fatal(err)
		}

		if slices.CompareFunc(
			lamport1,
			wantedLamport,
			func(a []byte, b string) int { return strings.Compare(hex.EncodeToString(a), b) },
		) != 0 {
			t.Fatal("Invalid lamport1 calculation")
		}
	}

	var test struct {
		Seed     string   `json:"seed"`
		Index    uint32   `json:"index"`
		Lamport1 []string `json:"lamport_1"`
	}

	file, err := os.Open("tests/derive_lamport_1.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&test); err != nil {
		t.Fatal(err)
	}

	f(t, test.Seed, test.Index, test.Lamport1)
}

func Test_deriveLamportPublicKeyFromParentKey(t *testing.T) {
	f := func(t *testing.T, seedHex string, index uint32, wantedKey string) {
		seed, err := hex.DecodeString(seedHex)
		if err != nil {
			t.Fatal(err)
		}

		masterSecretKey, err := deriveMasterSecretKey(seed)
		if err != nil {
			t.Fatal(err)
		}

		lamportPublicKey, err := deriveLamportPublicKeyFromParentKey(
			masterSecretKey,
			index,
		)
		if err != nil {
			t.Fatal(err)
		}

		if hex.EncodeToString(lamportPublicKey) != wantedKey {
			t.Fatalf(
				"Invalid lamport public key:\nWant: %s\nGot:  %s",
				wantedKey,
				hex.EncodeToString(lamportPublicKey),
			)
		}
	}

	var test struct {
		Seed      string `json:"seed"`
		Index     uint32 `json:"index"`
		LamportPK string `json:"lamport_PK"`
	}

	file, err := os.Open("tests/derive_parent_SK_to_lamport_PK.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&test); err != nil {
		t.Fatal(err)
	}

	f(t, test.Seed, test.Index, test.LamportPK)
}
