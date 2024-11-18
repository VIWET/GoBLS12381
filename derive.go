package gobls12381

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

const (
	// R is the order of the BLS 12-381 curve defined in the v4 draft IETF BLS signature scheme standard
	R = "52435875175126190479447740508185965837690552500527637822603658699938581184513"
	// L is the integer given by ceil((3 * ceil(log2(R))) / 16),
	L = 48
	// ASCII string comprising 20 octets
	Salt = "BLS-SIG-KEYGEN-SALT-"

	// Length of the input seed
	SeedLength = 32
)

var (
	r, _ = new(big.Int).SetString(R, 10)
	zero = new(big.Int).SetUint64(0)

	ErrInvalidSeed = errors.New("seed length must be greater than 32 byte")
)

// derive_master_SK
//
//	Inputs
//		seed, the source entropy for the entire tree, a octet string >= 256 bits in length
//	Outputs
//		SK, the secret key of master node within the tree, a big endian encoded integer
func deriveMasterSecretKey(seed []byte) (*big.Int, error) {
	if !isValidSeed(seed) {
		return nil, ErrInvalidSeed
	}

	return deriveHKDFModR(seed)
}

// isValidSeed returns false if seed length is less than 32 bytes
func isValidSeed(seed []byte) bool {
	return len(seed) >= 32
}

// hkdf_mod_r() is used to hash 32 random bytes into the subgroup of the BLS12-381 private keys.
//
//	Inputs:
//		IKM, a secret octet string >= 256 bits in length
//		key_info, an optional octet string (default="", the empty string)
//
//	Outputs:
//		SK, the corresponding secret key, an integer 0 <= SK < r.
func deriveHKDFModR(ikm []byte, keyInfo ...byte) (*big.Int, error) {
	var (
		ikmPostfix     = byte(0x00)
		keyInfoPostfix = make([]byte, 2)
		salt           = sha256.Sum256([]byte(Salt))
	)

	binary.BigEndian.PutUint16(keyInfoPostfix[:], L)

	ikm = append(ikm, ikmPostfix)
	keyInfo = append(keyInfo, keyInfoPostfix...)

	key := new(big.Int).SetUint64(0)
	for key.Cmp(zero) == 0 {
		prk := hkdf.Extract(sha256.New, ikm, salt[:])
		okmReader := hkdf.Expand(sha256.New, prk, keyInfo)

		okm := make([]byte, L)
		if _, err := okmReader.Read(okm); err != nil {
			return nil, err
		}

		key.Mod(new(big.Int).SetBytes(okm), r)
	}

	return key, nil
}
