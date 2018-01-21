package srpclient

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

type clientTest interface {
	SRPClient
	UpdateLastActivityTime()
	GetLastActivityTime() time.Time
	GetTimeout() time.Duration
	HasTimedOut() bool
	SetGeneratePrivateValue(func(r *rand.Rand, n *big.Int) *big.Int)
}

func TestNewSRPClient(t *testing.T) {
	var c SRPClient
	var err error

	// Test with nil hash function (should return an error).
	var h hash.Hash
	c, err = New(h)
	assert.NotNil(t, err)
	assert.Nil(t, c)

	// Test with valid hash function.
	c, err = New(sha1.New())
	assert.Nil(t, err)
	assert.NotNil(t, c)
}

func TestSetTimeout(t *testing.T) {
	var c SRPClient
	var err error

	// Test with invalid timeout.
	var invalidTimeouts = []time.Duration{-10 * time.Second, -1 * time.Second}

	for _, invalidTimeout := range invalidTimeouts {
		c, err = New(sha1.New(), Timeout(invalidTimeout))
		assert.NotNil(t, err)
		assert.Nil(t, c)
	}

	// Test with valid timeout.
	var validTimeouts = []time.Duration{0, 1 * time.Millisecond, 1 * time.Second}

	for _, validTimeout := range validTimeouts {
		c, err = New(sha1.New(), Timeout(validTimeout))
		assert.Nil(t, err)
		assert.NotNil(t, c)
	}
}

func TestSetGroup(t *testing.T) {
	var c SRPClient
	var err error

	// Test with invalid group.
	var invalidGrps = []*srp.Group{
		&srp.Group{Prime: nil, Generator: nil},
		&srp.Group{Prime: nil, Generator: big.NewInt(0)},
		&srp.Group{Prime: big.NewInt(0), Generator: nil},
	}

	for _, invalidGrp := range invalidGrps {
		c, err = New(sha1.New(), Group(invalidGrp))
		assert.NotNil(t, err)
		assert.Nil(t, c)
	}

	// Test with valid group.
	var validGrpNames = []string{"rfc-1024", "rfc-1536", "rfc-2048", "rfc-3072", "rfc-4096", "rfc-6144", "rfc-8192"}

	for _, validGrpName := range validGrpNames {
		var validGrp, err = srp.GetGroup(validGrpName)
		assert.Nil(t, err)
		c, err = New(sha1.New(), Group(validGrp))
		assert.Nil(t, err)
		assert.NotNil(t, c)
	}
}

func TestSetComputeX(t *testing.T) {
	var c SRPClient
	var err error

	// Test with invalid function.
	var invalidComputeXs = []srp.ComputeX{nil}

	for _, invalidComputeX := range invalidComputeXs {
		c, err = New(sha1.New(), ComputeX(invalidComputeX))
		assert.NotNil(t, err)
		assert.Nil(t, c)
	}

	// Test with valid function.
	var validComputeXs = []srp.ComputeX{srp.ComputeXWithoutUsername, srp.ComputeXWithUsername}

	for _, validComputeX := range validComputeXs {
		c, err = New(sha1.New(), ComputeX(validComputeX))
		assert.Nil(t, err)
		assert.NotNil(t, c)
	}
}

func TestUpdateLastActivityTime(t *testing.T) {
	var client SRPClient
	var err error

	client, err = New(sha1.New())
	assert.Nil(t, err)

	var ok bool
	var c clientTest
	c, ok = client.(clientTest)
	assert.True(t, ok)

	// Get current timestamp
	var timestamp = c.GetLastActivityTime()
	assert.NotNil(t, timestamp)

	// Update timestamp
	c.UpdateLastActivityTime()

	// Get new timestamp
	var newTimestamp = c.GetLastActivityTime()

	// Check that the timestamp was updated
	assert.True(t, newTimestamp.After(timestamp))
}

func TestUpdateTimeout(t *testing.T) {
	var client SRPClient
	var err error

	var timeouts = []time.Duration{1 * time.Second, 2 * time.Second, 10 * time.Second}

	for _, timeout := range timeouts {
		client, err = New(sha1.New(), Timeout(timeout))
		assert.Nil(t, err)

		var ok bool
		var c clientTest
		c, ok = client.(clientTest)
		assert.True(t, ok)

		// Get current timeout
		assert.Equal(t, timeout, c.GetTimeout())
	}
}

func TestHasTimedOut(t *testing.T) {
	var client SRPClient
	var err error

	// Test with no timeout.
	client, err = New(sha1.New(), Timeout(0))
	assert.Nil(t, err)

	var ok bool
	var c clientTest
	c, ok = client.(clientTest)
	assert.True(t, ok)

	assert.False(t, c.HasTimedOut())

	// Test with timeout.
	var timeout = 1 * time.Millisecond
	client, err = New(sha1.New(), Timeout(timeout))
	assert.Nil(t, err)

	c, ok = client.(clientTest)
	assert.True(t, ok)

	// Sleep to ensure we have a timeout.
	time.Sleep(2 * timeout)
	assert.True(t, c.HasTimedOut())
}

func TestStep1(t *testing.T) {
	var c SRPClient
	var err error

	var grp *srp.Group
	grp, err = srp.GetGroup("rfc-1024")
	assert.Nil(t, err)

	c, err = New(sha1.New(), Timeout(0), ComputeX(srp.ComputeXWithUsername), Group(grp))
	assert.Nil(t, err)

	// Empty userID.
	err = c.Step1("", "password123")
	assert.NotNil(t, err)

	// Empty password.
	err = c.Step1("alice", "")
	assert.NotNil(t, err)

	// Valid credentials.
	err = c.Step1("alice", "password123")
	assert.Nil(t, err)

	// State error.
	err = c.Step1("alice", "password123")
	assert.NotNil(t, err)
}

func TestStep2(t *testing.T) {
	var err error

	var grp *srp.Group
	grp, err = srp.GetGroup("rfc-1024")
	assert.Nil(t, err)

	var c clientTest
	{
		var err error
		var client SRPClient
		client, err = New(sha1.New(), Timeout(0), ComputeX(srp.ComputeXWithUsername), Group(grp))
		assert.Nil(t, err)

		var ok bool
		c, ok = client.(clientTest)
		assert.True(t, ok)
	}

	// Set the private client value. Here we match the one in the test vector.
	c.SetGeneratePrivateValue(func(r *rand.Rand, n *big.Int) *big.Int {
		return srp.GetBigIntFromHex("60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD DA2D4393")
	})

	// The test vector come from the RFC 5054 (https://www.ietf.org/rfc/rfc5054.txt)
	var salt = srp.GetBigIntFromHex("BEB25379 D1A8581E B5A72767 3A2441EE").Bytes()
	var publicServerValue = srp.GetBigIntFromHex("BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011 BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99 6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA 37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE EB4012B7 D7665238 A8E3FB00 4B117B58")
	var expectedPublicClientValue = srp.GetBigIntFromHex("61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4 4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC 8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44 BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA B349EF5D 76988A36 72FAC47B 0769447B")

	var publicClientValue *big.Int
	var clientEvidence *big.Int

	// Should return invalid state error.
	publicClientValue, clientEvidence, err = c.Step2(salt, publicServerValue)
	assert.NotNil(t, err)

	// Execute Step1 to go in valid state.
	err = c.Step1("alice", "password123")
	assert.Nil(t, err)

	// Test with nil salt.
	publicClientValue, clientEvidence, err = c.Step2(nil, publicServerValue)
	assert.NotNil(t, err)

	// Test with nil publicServerValue.
	publicClientValue, clientEvidence, err = c.Step2(salt, nil)
	assert.NotNil(t, err)

	// Test with invalid publicServerValue.
	publicClientValue, clientEvidence, err = c.Step2(salt, big.NewInt(0))
	assert.NotNil(t, err)

	// Test with valid parameters.
	publicClientValue, clientEvidence, err = c.Step2(salt, publicServerValue)
	assert.Equal(t, expectedPublicClientValue, publicClientValue)
	assert.NotNil(t, clientEvidence)
}

func TestStep3(t *testing.T) {
	var err error

	var grp *srp.Group
	grp, err = srp.GetGroup("rfc-1024")
	assert.Nil(t, err)

	var c clientTest
	{
		var err error
		var client SRPClient
		client, err = New(sha1.New(), Timeout(0), ComputeX(srp.ComputeXWithUsername), Group(grp))
		assert.Nil(t, err)

		var ok bool
		c, ok = client.(clientTest)
		assert.True(t, ok)
	}

	// Set the private client value. Here we match the one in the test vector.
	c.SetGeneratePrivateValue(func(r *rand.Rand, n *big.Int) *big.Int {
		return srp.GetBigIntFromHex("60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD DA2D4393")
	})

	// The test vector come from the RFC 5054 (https://www.ietf.org/rfc/rfc5054.txt)
	var salt = srp.GetBigIntFromHex("BEB25379 D1A8581E B5A72767 3A2441EE").Bytes()
	var publicServerValue = srp.GetBigIntFromHex("BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011 BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99 6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA 37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE EB4012B7 D7665238 A8E3FB00 4B117B58")
	var serverEvidence = srp.GetBigIntFromHex("B0A6AD30 24E79b5C AD04042A BB3A3F59 2D20C17")

	// Should return invalid state error.
	err = c.Step3(publicServerValue)
	assert.NotNil(t, err)

	// Execute Step1. It should still return an invalid state error.
	err = c.Step1("alice", "password123")
	assert.Nil(t, err)
	err = c.Step3(publicServerValue)
	assert.NotNil(t, err)

	// Execute Step2.
	_, _, err = c.Step2(salt, publicServerValue)

	err = c.Step3(serverEvidence)
	assert.Nil(t, err)
}

/*
func TestSrpAuth(t *testing.T) {
	var logger = log.NewLogfmtLogger(ioutil.Discard)

	var err error

	var verifierGen VerifierGenerator
	{
		var err error
		verifierGen, err = verifierNewVerifierGenerator(logger)
		assert.Nil(t, err)
	}
	var client SRPClient
	{
		var err error
		client = newSrpClient(config, 0, logger)
		assert.Nil(t, err)
	}
	var server ServerSrp
	{
		var err error
		server = newSrpServer(config, 0, logger)
		assert.Nil(t, err)
	}

	// Srp authentication
	var username = "Alice"
	var password = "P@ssw0rd"
	var salt = make([]byte, 10)
	r.Read(salt)
	var s = big.NewInt(0).SetBytes(salt)

	// Generate verifier
	var verifierAlice *big.Int = verifierGen.GenerateVerifier(salt, username, password)

	// Client, step 1
	err = client.Step1(username, password)
	assert.Nil(t, err)

	// Server, step 1
	var B *big.Int
	B, err = server.Step1(username, s, verifierAlice)
	assert.Nil(t, err)

	// Client, step2
	var cc ClientCredentials
	cc, err = client.Step2(s, B)
	assert.Nil(t, err)

	// Server, step2
	var M2 *big.Int
	M2, err = server.Step2(cc.PublicClientValue, cc.ClientEvidence)
	assert.Nil(t, err)

	// Client, step2
	err = client.Step3(M2)
	assert.Nil(t, err)

}
*/
