package gobls12381

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
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

	// KeyChunkCount is the HKDF output size
	KeyChunkCount = 255
	// KeyChunkSize is the digest size (in octets) of the hash function (SHA256)
	KeyChunkSize = 32
)

var (
	r, _ = new(big.Int).SetString(R, 10)
	zero = new(big.Int).SetUint64(0)
	one  = new(big.Int).SetUint64(1)

	// ErrInvalidSeed
	ErrInvalidSeed = errors.New("seed length must be greater than 32 byte")
)

// DeriveKey from seed and path
func DeriveKey(seed []byte, path string) (*big.Int, error) {
	indices, err := parsePath(path)
	if err != nil {
		return nil, err
	}

	key, err := deriveMasterSecretKey(seed)
	if err != nil {
		return nil, err
	}

	for _, index := range indices {
		key, err = deriveChildSecretKey(key, index)
		if err != nil {
			return nil, err
		}
	}

	return key, nil
}

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

// derive_child_SK
//
//	Inputs
//		parent_SK, the secret key of the parent node, a big endian encoded integer
//		index, the index of the desired child node, an integer 0 <= index < 2^32
//	Outputs
//		child_SK, the secret key of the child node, a big endian encoded integer
func deriveChildSecretKey(parentKey *big.Int, index uint32) (*big.Int, error) {
	lamportPublicKey, err := deriveLamportPublicKeyFromParentKey(parentKey, index)
	if err != nil {
		return nil, err
	}

	return deriveHKDFModR(lamportPublicKey)
}

// isValidSeed returns false if seed length is less than 32 bytes
func isValidSeed(seed []byte) bool {
	return len(seed) >= 32
}

// hkdf_mod_r() is used to hash 32 random bytes into the subgroup of the BLS12-381 private keys.
//
//	Inputs
//		IKM, a secret octet string >= 256 bits in length
//		key_info, an optional octet string (default="", the empty string)
//
//	Outputs
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

// IKM_to_lamport_SK
//
//	Inputs
//		IKM, a secret octet string
//		salt, an octet string
//	Outputs
//		lamport_SK, an array of 255 32-octet strings
func deriveLamportSecretKeyFromIKM(ikm []byte, salt []byte) ([][]byte, error) {
	prk := hkdf.Extract(sha256.New, ikm, salt[:])
	okmReader := hkdf.Expand(sha256.New, prk, []byte(nil))

	lamportKey := make([][]byte, KeyChunkCount)
	for i := 0; i < KeyChunkCount; i++ {
		lamportKey[i] = make([]byte, KeyChunkSize)
		if _, err := okmReader.Read(lamportKey[i]); err != nil {
			return nil, fmt.Errorf("failed to read from OKMReader: %w", err)
		}
	}

	return lamportKey, nil
}

// parent_SK_to_lamport_PK
//
//	Inputs
//		parent_SK, the BLS Secret Key of the parent node
//		index, the index of the desired child node, an integer 0 <= index < 2^32
//	Outputs
//		lamport_PK, the compressed lamport PK, a 32 octet string
func deriveLamportPublicKeyFromParentKey(parentKey *big.Int, index uint32) ([]byte, error) {
	salt := make([]byte, 4)
	binary.BigEndian.PutUint32(salt, index)

	lamport0, err := deriveLamport0(parentKey, salt)
	if err != nil {
		return nil, err
	}

	lamport1, err := deriveLamport1(parentKey, salt)
	if err != nil {
		return nil, err
	}

	composedLamportPublicKey := make([]byte, 2*KeyChunkCount*KeyChunkSize)
	for i := 0; i < KeyChunkCount; i++ {
		from := i * KeyChunkSize
		to := (i + 1) * KeyChunkSize
		element := sha256.Sum256(lamport0[i])
		copy(composedLamportPublicKey[from:to], element[:])

		from += KeyChunkCount * KeyChunkSize
		to += KeyChunkCount * KeyChunkSize
		element = sha256.Sum256(lamport1[i])
		copy(composedLamportPublicKey[from:to], element[:])
	}

	compressedLamportPublicKey := sha256.Sum256(composedLamportPublicKey)
	return compressedLamportPublicKey[:], nil
}

// deriveLamport0 calls IKM_to_lamport_SK with parentKey as IKM
func deriveLamport0(parentKey *big.Int, salt []byte) ([][]byte, error) {
	ikm := parentKey.Bytes()
	return deriveLamportSecretKeyFromIKM(ikm, salt)
}

// deriveLamport1 calls IKM_to_lamport_SK with flipped parentKey as IKM
func deriveLamport1(parentKey *big.Int, salt []byte) ([][]byte, error) {
	ikm := flipBits(parentKey, 256).Bytes()
	return deriveLamportSecretKeyFromIKM(ikm, salt)
}

// flipBits is a function that returns the bitwise negation of its input
func flipBits(key *big.Int, bitlen uint) *big.Int {
	mask := new(big.Int).Sub(
		new(big.Int).Lsh(one, bitlen),
		one,
	)

	return new(big.Int).Xor(key, mask)
}
