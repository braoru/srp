package srpserver

import (
	"fmt"
	"hash"
	"math/big"
	"math/rand"
	"time"

	"github.com/JohanDroz/srp"
)

// SRPServer is the srp server interface.
type SRPServer interface {
	Step1(userID string, salt []byte, verifier *big.Int) (publicServerValue *big.Int, err error)
	Step2(publicClientValue, clientEvidence *big.Int) (serverEvidence *big.Int, err error)
}

type session struct {
	userID               string   // I
	salt                 []byte   // s
	publicClientValue    *big.Int // A
	publicServerValue    *big.Int // B
	privateServerValue   *big.Int // b
	scramblingParam      *big.Int // u
	multiplier           *big.Int // k
	sessionKey           *big.Int // S
	clientEvidence       *big.Int // M1
	serverEvidence       *big.Int // M2
	verifier             *big.Int // v
	noSuchUserIdentity   bool
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

func New(hash hash.Hash, options ...option) (SRPServer, error) {

	if hash == nil {
		return nil, fmt.Errorf("the hash function must not be nil")
	}

	var defaultGrp, err = srp.GetGroup("rfc-1024")
	if err != nil {
		return nil, err
	}

	var srpServer = &session{
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
		var err = opt(srpServer)
		if err != nil {
			return nil, err
		}
	}

	return srpServer, nil
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

func (s *session) Step1(userID string, salt []byte, v *big.Int) (*big.Int, error) {

	// Validate inputs
	if userID == "" {
		return nil, fmt.Errorf("The user identity must not be empty")
	}
	s.userID = userID

	if salt == nil {
		return nil, fmt.Errorf("The salt must not be nil")
	}
	s.salt = salt

	if v == nil {
		return nil, fmt.Errorf("The verifier must not be nil")
	}
	s.verifier = v

	// Check current state
	if s.state != srp.Init {
		return nil, fmt.Errorf("State violation: Session must be in 'Init' state")
	}
	s.multiplier = srp.ComputeMultiplier(s.hash, s.grp.Prime, s.grp.Generator)
	s.privateServerValue = s.generatePrivateValue(s.rand, s.grp.Prime)
	s.publicServerValue = srp.ComputePublicServerValue(s.grp.Prime, s.grp.Generator, s.multiplier, s.verifier, s.privateServerValue)

	s.state = srp.Step1
	s.UpdateLastActivityTime()

	return s.publicServerValue, nil
}

func (s *session) Step2(publicClientValue, clientEvidence *big.Int) (*big.Int, error) {

	// Validate inputs
	if publicClientValue == nil {
		return nil, fmt.Errorf("The client public value must not be nil")
	}
	s.publicClientValue = publicClientValue

	if clientEvidence == nil {
		return nil, fmt.Errorf("The client evidence message must not be nil")
	}
	s.clientEvidence = clientEvidence

	// Check current state
	if s.state != srp.Step1 {
		return nil, fmt.Errorf("State violation: Session must be in 'Step1' state")
	}

	// Check timeout
	if s.HasTimedOut() {
		return nil, fmt.Errorf("Session timeout")
	}

	// Check A validity
	if !srp.IsValidPublicValue(s.grp.Prime, s.publicClientValue) {
		return nil, fmt.Errorf("Bad client public value")
	}

	s.scramblingParam = srp.ComputeScramblingParameter(s.hash, s.grp.Prime, s.publicClientValue, s.publicServerValue)
	s.sessionKey = srp.ComputeServerSessionKey(s.grp.Prime, s.verifier, s.scramblingParam, s.publicClientValue, s.privateServerValue)

	// Compute the own client evidence message
	var computedM1 = srp.ComputeClientEvidence(s.hash, s.publicClientValue, s.publicServerValue, s.sessionKey)

	if computedM1.Cmp(s.clientEvidence) != 0 {
		return nil, fmt.Errorf("Bad client credentials")
	}

	s.state = srp.Step2
	s.serverEvidence = srp.ComputeServerEvidence(s.hash, s.publicClientValue, s.clientEvidence, s.sessionKey)
	s.UpdateLastActivityTime()

	return s.serverEvidence, nil
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

func ComputeX(computeX srp.ComputeX) option {
	return func(s *session) error {
		if computeX == nil {
			return fmt.Errorf("the compute x function should not be nil")
		}
		s.computeX = computeX
		return nil
	}
}

// SetGeneratePrivateValue set the function that generate the private values. It is used in the tests
// to control the values returned (while it is usually random).
func (s *session) SetGeneratePrivateValue(f func(r *rand.Rand, n *big.Int) *big.Int) {
	s.generatePrivateValue = f
}
