package secure_network

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/gddisney/logger"
	"github.com/gddisney/secure_policy"
	"github.com/gddisney/service_keys"
	"github.com/gddisney/ultimate_db"
	"github.com/gddisney/webauthnext"
	"github.com/gddisney/guikit"
)

func createTestNode(
	t *testing.T,
	db *ultimate_db.DB,
) *SecureNode {

	t.Helper()

	logDisp, err := logger.NewLogDispatcher(
		"test_node",
		db,
		ConfigPageID,
		100,
	)

	if err != nil {
		t.Fatalf(
			"failed creating logger: %v",
			err,
		)
	}

	node, err := NewSecureNode(
		db,
		logDisp,
		"localhost",
		"http://localhost",
		"Secure Test",
		nil,
	)

	if err != nil {
		t.Fatalf(
			"failed creating secure node: %v",
			err,
		)
	}

	return node
}

func TestPolicyEngineInitialization(
	t *testing.T,
) {

	db := &ultimate_db.DB{}

	engine := secure_policy.NewPolicyEngine(
		db,
	)

	if engine == nil {

		t.Fatal(
			"policy engine is nil",
		)
	}
}

func TestSessionManagerInitialization(
	t *testing.T,
) {

	db := &ultimate_db.DB{}

	rsaPriv, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)

	if err != nil {

		t.Fatalf(
			"rsa generation failed: %v",
			err,
		)
	}

	manager := secure_policy.NewSessionManager(
		db,
		rsaPriv,
	)

	if manager == nil {

		t.Fatal(
			"session manager is nil",
		)
	}
}

func TestServiceKeyManagerInitialization(
	t *testing.T,
) {

	db := &ultimate_db.DB{}

	manager := service_keys.NewServiceKeyManager(
		db,
		nil,
		nil,
	)

	if manager == nil {

		t.Fatal(
			"service key manager is nil",
		)
	}
}

func TestGossipIngress(
	t *testing.T,
) {

	db := &ultimate_db.DB{}

	logDisp, _ := logger.NewLogDispatcher(
		"gossip_test",
		db,
		ConfigPageID,
		100,
	)

	peerRoute := &PeerRoute{}

	skm := service_keys.NewServiceKeyManager(
		db,
		nil,
		logDisp,
	)

	gossip := NewGossipManager(
		db,
		peerRoute,
		skm,
		logDisp,
	)

	payload := []byte(`{
		"id":"test-msg",
		"service_id":"test",
		"payload":"aGVsbG8=",
		"signature":"dGVzdA==",
		"lamport":1
	}`)

	err := gossip.HandleIngress(
		context.Background(),
		payload,
	)

	if err == nil {

		t.Log(
			"gossip ingress executed",
		)
	}
}

func TestWebAuthnProvider(
	t *testing.T,
) {

	db := &ultimate_db.DB{}

	rsaPriv, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)

	if err != nil {

		t.Fatalf(
			"rsa generation failed: %v",
			err,
		)
	}

	sessionManager := secure_policy.NewSessionManager(
		db,
		rsaPriv,
	)

	gui := &guikit.GUIKit{}

	provider, err := webauthnext.New(
		gui,
		sessionManager,
		"localhost",
		"http://localhost",
		"Secure Test",
	)

	if err != nil {

		t.Fatalf(
			"webauthn init failed: %v",
			err,
		)
	}

	if provider == nil {

		t.Fatal(
			"provider is nil",
		)
	}
}

func TestSecureNodeInitialization(
	t *testing.T,
) {

	db := &ultimate_db.DB{}

	node := createTestNode(
		t,
		db,
	)

	if node == nil {

		t.Fatal(
			"node is nil",
		)
	}

	if node.Mesh == nil {

		t.Fatal(
			"mesh subsystem missing",
		)
	}

	if node.RPC == nil {

		t.Fatal(
			"rpc subsystem missing",
		)
	}

	if node.Gossip == nil {

		t.Fatal(
			"gossip subsystem missing",
		)
	}
}

func TestRPCRegistration(
	t *testing.T,
) {

	db := &ultimate_db.DB{}

	node := createTestNode(
		t,
		db,
	)

	called := false

	node.RegisterRPC(
		"ping",
		func(
			ctx context.Context,
			payload []byte,
		) ([]byte, error) {

			called = true

			return []byte("pong"), nil
		},
	)

	handler, ok := node.RPC.handlers["ping"]

	if !ok {

		t.Fatal(
			"rpc handler not registered",
		)
	}

	_, err := handler(
		context.Background(),
		[]byte("hello"),
	)

	if err != nil {

		t.Fatalf(
			"handler execution failed: %v",
			err,
		)
	}

	if !called {

		t.Fatal(
			"handler was not executed",
		)
	}
}

func TestGossipRegistration(
	t *testing.T,
) {

	db := &ultimate_db.DB{}

	node := createTestNode(
		t,
		db,
	)

	called := false

	node.RegisterGossip(
		"test-service",
		func(
			ctx context.Context,
			env *GossipEnvelope,
		) error {

			called = true
			return nil
		},
	)

	handler, ok := node.Gossip.handlers["test-service"]

	if !ok {

		t.Fatal(
			"gossip handler missing",
		)
	}

	err := handler(
		context.Background(),
		&GossipEnvelope{},
	)

	if err != nil {

		t.Fatalf(
			"handler execution failed: %v",
			err,
		)
	}

	if !called {

		t.Fatal(
			"handler not called",
		)
	}
}

func TestPeerRouteLifecycle(
	t *testing.T,
) {

	db := &ultimate_db.DB{}

	node := createTestNode(
		t,
		db,
	)

	var nodeID NodeID

	copy(
		nodeID[:],
		[]byte("peer-1"),
	)

	peer := &PeerIdentity{
		NodeID:    nodeID,
		PublicKey: []byte("pub"),
		Address:   "127.0.0.1",
		LastSeen:  time.Now(),
	}

	node.PeerRoute.AddPeer(
		peer,
	)

	if node.PeerRoute.PeerCount() != 1 {

		t.Fatal(
			"peer count mismatch",
		)
	}

	node.PeerRoute.RemovePeer(
		nodeID,
	)

	if node.PeerRoute.PeerCount() != 0 {

		t.Fatal(
			"peer removal failed",
		)
	}
}
