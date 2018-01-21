package srpserver

import (
	"crypto/sha1"
	"hash"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/JohanDroz/srp"
	"github.com/stretchr/testify/assert"
)

type serverTest interface {
	SRPServer
	UpdateLastActivityTime()
	GetLastActivityTime() time.Time
	GetTimeout() time.Duration
	HasTimedOut() bool
	SetGeneratePrivateValue(func(r *rand.Rand, n *big.Int) *big.Int)
}

func TestNewSRPServer(t *testing.T) {
	var s SRPServer
	var err error

	// Test with nil hash function (should return an error).
	var h hash.Hash
	s, err = New(h)
	assert.NotNil(t, err)
	assert.Nil(t, s)

	// Test with valid hash function.
	s, err = New(sha1.New())
	assert.Nil(t, err)
	assert.NotNil(t, s)
}

func TestSetTimeout(t *testing.T) {
	var s SRPServer
	var err error

	// Test with invalid timeout.
	var invalidTimeouts = []time.Duration{-10 * time.Second, -1 * time.Second}

	for _, invalidTimeout := range invalidTimeouts {
		s, err = New(sha1.New(), Timeout(invalidTimeout))
		assert.NotNil(t, err)
		assert.Nil(t, s)
	}

	// Test with valid timeout.
	var validTimeouts = []time.Duration{0, 1 * time.Millisecond, 1 * time.Second}

	for _, validTimeout := range validTimeouts {
		s, err = New(sha1.New(), Timeout(validTimeout))
		assert.Nil(t, err)
		assert.NotNil(t, s)
	}
}

func TestSetGroup(t *testing.T) {
	var s SRPServer
	var err error

	// Test with invalid group.
	var invalidGrps = []*srp.Group{
		&srp.Group{Prime: nil, Generator: nil},
		&srp.Group{Prime: nil, Generator: big.NewInt(0)},
		&srp.Group{Prime: big.NewInt(0), Generator: nil},
	}

	for _, invalidGrp := range invalidGrps {
		s, err = New(sha1.New(), Group(invalidGrp))
		assert.NotNil(t, err)
		assert.Nil(t, s)
	}

	// Test with valid group.
	var validGrpNames = []string{"rfc-1024", "rfc-1536", "rfc-2048", "rfc-3072", "rfc-4096", "rfc-6144", "rfc-8192"}

	for _, validGrpName := range validGrpNames {
		var validGrp, err = srp.GetGroup(validGrpName)
		assert.Nil(t, err)
		s, err = New(sha1.New(), Group(validGrp))
		assert.Nil(t, err)
		assert.NotNil(t, s)
	}
}

func TestSetComputeX(t *testing.T) {
	var s SRPServer
	var err error

	// Test with invalid function.
	var invalidComputeXs = []srp.ComputeX{nil}

	for _, invalidComputeX := range invalidComputeXs {
		s, err = New(sha1.New(), ComputeX(invalidComputeX))
		assert.NotNil(t, err)
		assert.Nil(t, s)
	}

	// Test with valid function.
	var validComputeXs = []srp.ComputeX{srp.ComputeXWithoutUsername, srp.ComputeXWithUsername}

	for _, validComputeX := range validComputeXs {
		s, err = New(sha1.New(), ComputeX(validComputeX))
		assert.Nil(t, err)
		assert.NotNil(t, s)
	}
}
func TestUpdateLastActivityTime(t *testing.T) {
	var server SRPServer
	var err error

	server, err = New(sha1.New())
	assert.Nil(t, err)

	var ok bool
	var s serverTest
	s, ok = server.(serverTest)
	assert.True(t, ok)

	// Get current timestamp
	var timestamp = s.GetLastActivityTime()
	assert.NotNil(t, timestamp)

	// Update timestamp
	s.UpdateLastActivityTime()

	// Get new timestamp
	var newTimestamp = s.GetLastActivityTime()

	// Check that the timestamp was updated
	assert.True(t, newTimestamp.After(timestamp))
}

func TestUpdateTimeout(t *testing.T) {
	var server SRPServer
	var err error

	var timeouts = []time.Duration{1 * time.Second, 2 * time.Second, 10 * time.Second}

	for _, timeout := range timeouts {
		server, err = New(sha1.New(), Timeout(timeout))
		assert.Nil(t, err)

		var ok bool
		var s serverTest
		s, ok = server.(serverTest)
		assert.True(t, ok)

		// Get current timeout
		assert.Equal(t, timeout, s.GetTimeout())
	}
}

func TestHasTimedOut(t *testing.T) {
	var server SRPServer
	var err error

	// Test with no timeout.
	server, err = New(sha1.New(), Timeout(0))
	assert.Nil(t, err)

	var ok bool
	var c serverTest
	c, ok = server.(serverTest)
	assert.True(t, ok)

	assert.False(t, c.HasTimedOut())

	// Test with timeout.
	var timeout = 1 * time.Millisecond
	server, err = New(sha1.New(), Timeout(timeout))
	assert.Nil(t, err)

	c, ok = server.(serverTest)
	assert.True(t, ok)

	// Sleep to ensure we have a timeout.
	time.Sleep(2 * timeout)
	assert.True(t, c.HasTimedOut())
}

func TestStep1(t *testing.T) {
	var err error

	var grp *srp.Group
	grp, err = srp.GetGroup("rfc-1024")
	assert.Nil(t, err)

	var s serverTest
	{
		var err error
		var server SRPServer
		server, err = New(sha1.New(), Timeout(0), ComputeX(srp.ComputeXWithUsername), Group(grp))
		assert.Nil(t, err)

		var ok bool
		s, ok = server.(serverTest)
		assert.True(t, ok)
	}

	// The test vector come from the RFC 5054 (https://www.ietf.org/rfc/rfc5054.txt)
	var userID = "alice"
	var salt = srp.GetBigIntFromHex("BEB25379 D1A8581E B5A72767 3A2441EE").Bytes()
	var verifier = srp.GetBigIntFromHex("7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812 9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5 C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5 EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78 E955A5E2 9E7AB245 DB2BE315 E2099AFB")
	var expectedPublicServerValue = srp.GetBigIntFromHex("BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011 BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99 6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA 37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE EB4012B7 D7665238 A8E3FB00 4B117B58")

	// Set the private server value. Here we match the one in the test vector.
	s.SetGeneratePrivateValue(func(r *rand.Rand, n *big.Int) *big.Int {
		return srp.GetBigIntFromHex("E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1 05284D20")
	})

	var publicServerValue *big.Int

	// Empty userID
	publicServerValue, err = s.Step1("", salt, verifier)
	assert.NotNil(t, err)

	// nil salt
	publicServerValue, err = s.Step1(userID, nil, verifier)
	assert.NotNil(t, err)

	// nil verifier
	publicServerValue, err = s.Step1(userID, salt, nil)
	assert.NotNil(t, err)

	// Valid parameters
	publicServerValue, err = s.Step1(userID, salt, verifier)
	assert.Nil(t, err)
	assert.Equal(t, expectedPublicServerValue, publicServerValue)

	// State error
	publicServerValue, err = s.Step1(userID, salt, verifier)
	assert.NotNil(t, err)
}

func TestStep2(t *testing.T) {
	var err error

	var grp *srp.Group
	grp, err = srp.GetGroup("rfc-1024")
	assert.Nil(t, err)

	var s serverTest
	{
		var err error
		var server SRPServer
		server, err = New(sha1.New(), Timeout(0), ComputeX(srp.ComputeXWithUsername), Group(grp))
		assert.Nil(t, err)

		var ok bool
		s, ok = server.(serverTest)
		assert.True(t, ok)
	}

	// The test vector come from the RFC 5054 (https://www.ietf.org/rfc/rfc5054.txt)
	var userID = "alice"
	var salt = srp.GetBigIntFromHex("BEB25379 D1A8581E B5A72767 3A2441EE").Bytes()
	var verifier = srp.GetBigIntFromHex("7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812 9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5 C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5 EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78 E955A5E2 9E7AB245 DB2BE315 E2099AFB")
	var publicClientValue = srp.GetBigIntFromHex("61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4 4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC 8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44 BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA B349EF5D 76988A36 72FAC47B 0769447B")
	var clientEvidence = srp.GetBigIntFromHex("B46A7838 46B7E569 FF8F9B44 AB8D88ED EB085A65")
	var expectedServerEvidence = srp.GetBigIntFromHex("B0A6AD30 24E79b5C AD04042A BB3A3F59 2D20C17")

	// Set the private server value. Here we match the one in the test vector.
	s.SetGeneratePrivateValue(func(r *rand.Rand, n *big.Int) *big.Int {
		return srp.GetBigIntFromHex("E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1 05284D20")
	})

	var serverEvidence *big.Int

	// Should return invalid state error.
	serverEvidence, err = s.Step2(publicClientValue, clientEvidence)
	assert.NotNil(t, err)

	// Execute Step1 to go in valid state.
	_, err = s.Step1(userID, salt, verifier)
	assert.Nil(t, err)

	// Valid parameters.
	serverEvidence, err = s.Step2(publicClientValue, clientEvidence)

	assert.Nil(t, err)
	assert.Equal(t, expectedServerEvidence, serverEvidence)
}
