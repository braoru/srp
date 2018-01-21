package srpclient

import (
	"fmt"
	"hash"
	"math/big"
	"math/rand"
	"time"

	"github.com/JohanDroz/srp"
)

// SRPClient is the srp client interface.
type SRPClient interface {
	Step1(userID, password string) error
	Step2(salt []byte, publicServerValue *big.Int) (publicClientValue *big.Int, clientEvidence *big.Int, err error)
	Step3(serverEvidence *big.Int) error
}

type session struct {
	userID               string
	password             string
	salt                 []byte
	publicClientValue    *big.Int
	privateClientValue   *big.Int
	publicServerValue    *big.Int
	scramblingParam      *big.Int
	x                    *big.Int
	multiplier           *big.Int
	sessionKey           *big.Int
	clientEvidence       *big.Int
	serverEvidence       *big.Int
	hash                 hash.Hash
	rand                 *rand.Rand
	grp                  *srp.Group
	timeout              time.Duration
	lastActivity         time.Time
	computeX             srp.ComputeX
	state                int
	generatePrivateValue func(r *rand.Rand, n *big.Int) *big.Int
}

type option func(*session) error

// New returns a new SRP client.
func New(hash hash.Hash, options ...option) (SRPClient, error) {

	if hash == nil {
		return nil, fmt.Errorf("the hash function must not be nil")
	}

	var defaultGrp, err = srp.GetGroup("rfc-1024")
	if err != nil {
		return nil, err
	}

	var srpClient = &session{
		hash:                 hash,
		rand:                 rand.New(rand.NewSource(time.Now().UnixNano())),
		grp:                  defaultGrp,
		computeX:             srp.ComputeXWithoutUsername,
		timeout:              0,
		lastActivity:         time.Now(),
		state:                srp.Init,
		generatePrivateValue: srp.GeneratePrivateValue,
	}

	// Apply options to the SRPClient.
	for _, opt := range options {
		var err = opt(srpClient)
		if err != nil {
			return nil, err
		}
	}

	return srpClient, nil
}

// Update the last activity timestamp.
func (s *session) UpdateLastActivityTime() {
	s.lastActivity = time.Now()
}

// Get the last activity timestamp.
func (s *session) GetLastActivityTime() time.Time {
	return s.lastActivity
}

// Return the timeout configuration.
func (s *session) GetTimeout() time.Duration {
	return s.timeout
}

// Return true if the session has timed out, based on the
// timeout configuration and the last activity timestamp.
func (s *session) HasTimedOut() bool {
	if s.timeout == 0 {
		return false
	}
	var now = time.Now()

	return now.After(s.lastActivity.Add(s.timeout))
}

// Generate random salt s of length numBytes
func (s *session) generateRandomSalt(numBytes int) []byte {
	return srp.GenerateRandomSalt(s.rand, numBytes)
}

func (s *session) Step1(userID, password string) error {

	if userID == "" {
		return fmt.Errorf("The user identity must not be empty")
	}
	s.userID = userID

	if password == "" {
		return fmt.Errorf("The user password must not be empty")
	}
	s.password = password

	// Check current state
	if s.state != srp.Init {
		return fmt.Errorf("State violation: Session must be in 'Init' state")
	}
	s.state = srp.Step1
	s.UpdateLastActivityTime()

	return nil
}

func (s *session) Step2(salt []byte, publicServerValue *big.Int) (*big.Int, *big.Int, error) {

	if s.grp.Prime == nil || s.grp.Generator == nil {
		return nil, nil, fmt.Errorf("The SRP-6a crypto parameters must not be nil")
	}

	if s.hash == nil {
		return nil, nil, fmt.Errorf("The hash function must not be nil")
	}

	if salt == nil {
		return nil, nil, fmt.Errorf("The salt must not be nil")
	}
	s.salt = salt

	if publicServerValue == nil {
		return nil, nil, fmt.Errorf("The public server value must not be nil")
	}
	s.publicServerValue = publicServerValue

	// Check current state
	if s.state != srp.Step1 {
		return nil, nil, fmt.Errorf("State violation: Session must be in 'Step1' state")
	}

	// Check timeout
	if s.HasTimedOut() {
		return nil, nil, fmt.Errorf("Session timeout")
	}

	// Check public server value validity
	if !srp.IsValidPublicValue(s.grp.Prime, s.publicServerValue) {
		return nil, nil, fmt.Errorf("Bad server public value")
	}

	s.x = s.computeX(s.hash, s.salt, s.userID, s.password)
	s.privateClientValue = s.generatePrivateValue(s.rand, s.grp.Prime)
	s.publicClientValue = srp.ComputePublicClientValue(s.grp.Prime, s.grp.Generator, s.privateClientValue)
	s.multiplier = srp.ComputeMultiplier(s.hash, s.grp.Prime, s.grp.Generator)
	s.scramblingParam = srp.ComputeScramblingParameter(s.hash, s.grp.Prime, s.publicClientValue, s.publicServerValue)
	s.sessionKey = srp.ComputeClientSessionKey(s.grp.Prime, s.grp.Generator, s.multiplier, s.x, s.scramblingParam, s.privateClientValue, s.publicServerValue)
	s.clientEvidence = srp.ComputeClientEvidence(s.hash, s.publicClientValue, s.publicServerValue, s.sessionKey)

	s.state = srp.Step2
	s.UpdateLastActivityTime()

	return s.publicClientValue, s.clientEvidence, nil
}

func (s *session) Step3(serverEvidence *big.Int) error {

	// Validate input
	if serverEvidence == nil {
		return fmt.Errorf("The server evidence message must not be nil")
	}
	s.serverEvidence = serverEvidence

	// Check current state
	if s.state != srp.Step2 {
		return fmt.Errorf("State violation: Session must be in 'Step2' state")
	}

	// Check timeout
	if s.HasTimedOut() {
		return fmt.Errorf("Session timeout")
	}

	// Compute the own server evidence message
	var computedM2 = srp.ComputeServerEvidence(s.hash, s.publicClientValue, s.clientEvidence, s.sessionKey)

	if computedM2.Cmp(s.serverEvidence) != 0 {
		return fmt.Errorf("Bad server credentials")
	}
	s.state = srp.Step3
	s.UpdateLastActivityTime()

	return nil
}

func Timeout(t time.Duration) option {
	return func(s *session) error {
		if t < 0 {
			return fmt.Errorf("the timeout must be zero (no timeout) or greater")
		}
		s.timeout = t
		return nil
	}
}

func Group(grp *srp.Group) option {
	return func(s *session) error {
		if grp.Prime == nil || grp.Generator == nil {
			return fmt.Errorf("the prime and generator must not be nil")
		}
		s.grp = grp
		return nil
	}
}

// ComputeX allows to configure which function is used to compute the
// SRP x parameter.
func ComputeX(computeX srp.ComputeX) option {
	return func(s *session) error {
		if computeX == nil {
			return fmt.Errorf("the compute x function should not be nil")
		}
		s.computeX = computeX
		return nil
	}
}

// SetGeneratePrivateValue set the function that generete the private values. It is used in the tests
// to control the value returned (while it is usually random).
func (s *session) SetGeneratePrivateValue(f func(r *rand.Rand, n *big.Int) *big.Int) {
	s.generatePrivateValue = f
}
