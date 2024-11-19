package gobls12381

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	// Purpose is the name of the curve (BLS12-381)
	Purpose = 12381
	// CoinType reflects the coin number for an individual coin thereby acting as a means of separating the keys used for different chains
	CoinType = 3600
)

// WithdrawalKeyPath return a key path in form of m/12381/3600/i/0
func WithdrawalKeyPath(account uint32) string {
	return fmt.Sprintf("m/%d/%d/%d/0", Purpose, CoinType, account)
}

// SigningKeyPath returns a key path of m/12381/3600/i/0/0
func SigningKeyPath(account uint32) string {
	return fmt.Sprintf("m/%d/%d/%d/0/0", Purpose, CoinType, account)
}

// ErrInvalidPath
var ErrInvalidPath = errors.New("invalid path")

// parsePath returns the indices of child keys
func parsePath(path string) ([]uint32, error) {
	path = strings.ReplaceAll(path, " ", "")
	if !isValidPath(path) {
		return nil, ErrInvalidPath
	}

	nodes := strings.Split(path, "/")
	indices := make([]uint32, len(nodes)-1)
	for i := 1; i < len(nodes); i++ {
		index, err := strconv.ParseUint(nodes[i], 10, 32)
		if err != nil {
			return nil, err
		}

		indices[i-1] = uint32(index)
	}

	return indices, nil
}

var pathRegexp = regexp.MustCompile(`^m(\/[0-9]{1,})*$`)

// isValidPath returns false if path doesn't match the path regex
func isValidPath(path string) bool {
	return pathRegexp.MatchString(path)
}
