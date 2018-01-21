package verifier

import (
	"fmt"
	"hash"
	"math/big"

	"github.com/JohanDroz/srp"
)

type Generator interface {
	GenerateVerifier(salt []byte, username, password string) *big.Int
}

type generator struct {
	grp      *srp.Group
	hash     hash.Hash
	computeX srp.ComputeX
}

type option func(*generator) error

func New(hash hash.Hash, options ...option) (Generator, error) {

	if hash == nil {
		return nil, fmt.Errorf("the hash function must not be nil")
	}

	var defaultGrp, err = srp.GetGroup("rfc-2048")
	if err != nil {
		return nil, err
	}

	var verifierGen = &generator{
		grp:      defaultGrp,
		hash:     hash,
		computeX: srp.ComputeXWithoutUsername,
	}

	// Apply options to the Generator.
	for _, opt := range options {
		var err = opt(verifierGen)
		if err != nil {
			return nil, err
		}
	}

	return verifierGen, nil
}

func Group(grp *srp.Group) option {
	return func(g *generator) error {
		if grp.Prime == nil || grp.Generator == nil {
			return fmt.Errorf("the prime and generator must not be nil")
		}
		g.grp = grp
		return nil
	}
}

func ComputeX(computeX srp.ComputeX) option {
	return func(g *generator) error {
		if computeX == nil {
			return fmt.Errorf("the compute x function should not be nil")
		}
		g.computeX = computeX
		return nil
	}
}

// Generate verifier v for the specified parameters.
func (g *generator) GenerateVerifier(salt []byte, username, password string) *big.Int {
	var x = g.computeX(g.hash, salt, username, password)
	return srp.ComputeVerifier(g.grp.Prime, g.grp.Generator, x)
}
