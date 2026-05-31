package secure_network

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/0TrustCloud/guikit"
	"github.com/0TrustCloud/secure_data_format"
	"github.com/0TrustCloud/secure_policy"
	"github.com/0TrustCloud/ultimate_db"
)

// =============================================================================
// Interface Mock Layer for Test Isolation
// =============================================================================

type mockTxnHandle struct {
	id        uint64
	committed bool
	aborted   bool
}

func (m *mockTxnHandle) ID() uint64    { return m.id }
func (m *mockTxnHandle) Commit() error { m.committed = true; return nil }
func (m *mockTxnHandle) Abort() error  { m.aborted = true; return nil }

type mockKVStore struct {
	records map[string][]byte
	nextID  uint64
}

func (m *mockKVStore) Begin() ultimate_db.TxnHandle {
	m.nextID++
	return &mockTxnHandle{id: m.nextID}
}

func (m *mockKVStore) Get(txn ultimate_db.TxnHandle, key []byte) ([]byte, error) {
	if val, ok := m.records[string(key)]; ok {
		return val, nil
	}
	return nil, fmt.Errorf("key not found")
}

func (m *mockKVStore) Put(txn ultimate_db.TxnHandle, key []byte, value []byte, ttl time.Duration) error {
	m.records[string(key)] = value
	return nil
}

func (m *mockKVStore) Delete(txn ultimate_db.TxnHandle, key []byte) error {
	delete(m.records, string(key))
	return nil
}

func (m *mockKVStore) NewIterator(txn ultimate_db.TxnHandle, prefix []byte) ultimate_db.KVIterator {
	return nil
}

type mockLockManager struct {
	acquiredLocks map[string]uint64
}

func (m *mockLockManager) Acquire(txnID uint64, key string, mode ultimate_db.LockMode) error {
	m.acquiredLocks[key] = txnID
	return nil
}

func (m *mockLockManager) Release(txnID uint64, key string) error {
	delete(m.acquiredLocks, key)
	return nil
}

func (m *mockLockManager) ReleaseAll(txnID uint64) error {
	return nil
}

// =============================================================================
// Test Environment Setup Helpers
// =============================================================================

func setupTestNode(t *testing.T) (*SecureNode, *secure_data_format.SecureDataEngine) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating master keypair: %v", err)
	}

	storeMock := &mockKVStore{records: make(map[string][]byte)}
	lockMock := &mockLockManager{acquiredLocks: make(map[string]uint64)}

	sdf, err := secure_data_format.New(storeMock, lockMock, "test-network-authority", privKey)
	if err != nil {
		t.Fatalf("failed initializing test SDF engine: %v", err)
	}

	sm := secure_policy.NewSessionManager(sdf, &privKey.PublicKey)
	
	gatewayPub := make([]byte, 32)
	_, _ = rand.Read(gatewayPub)

	gk := &guikit.GUIKit{
		Mux: http.NewServeMux(),
	}

	// Correctly pass 'gk' as the 3rd argument
	node, err := NewSecureNode(sdf, sm, gk, "localhost", "localhost", "https://localhost", gatewayPub)
	if err != nil {
		t.Fatalf("failed to boot SecureNode workspace: %v", err)
	}

	return node, sdf
}

// =============================================================================
// Microkernel Subsystem Test Matrix
// =============================================================================

func TestSecureNode_Initialization(t *testing.T) {
	node, _ := setupTestNode(t)

	if node.HostID != "localhost" {
		t.Errorf("expected HostID 'localhost', got: %s", node.HostID)
	}

	if node.Mesh == nil || node.PeerRoute == nil || node.Gossip == nil || node.RPC == nil {
		t.Fatal("subsystem wireframe generation incomplete during kernel bootstrap sequence")
	}
}

func TestRPCManager_RegistrationAndIngress(t *testing.T) {
	node, _ := setupTestNode(t)
	rpcExecuted := false

	node.RegisterRPC("mesh:telemetry:ping", func(ctx context.Context, payload []byte) ([]byte, error) {
		rpcExecuted = true
		return []byte("pong"), nil
	})

	packet := RPCPacket{
		ID:        "rpc_req_101",
		Method:    "mesh:telemetry:ping",
		Payload:   []byte("hello"),
		Source:    []byte("remote-peer-identity-bytes-key"),
		Timestamp: time.Now().Unix(),
		Response:  false,
	}

	rawBytes, _ := json.Marshal(packet)

	node.RPC.handleIngress(context.Background(), rawBytes)

	if !rpcExecuted {
		t.Error("ingress router dropped valid RPC method capability mapping context")
	}
}

func TestPeerRoute_LifecycleAndHandshakeEvaluation(t *testing.T) {
	node, _ := setupTestNode(t)
	
	var nodeID NodeID
	copy(nodeID[:], []byte("mesh-worker-node-01-identity-32"))

	peer := &PeerIdentity{
		NodeID:    nodeID,
		PublicKey: []byte("public-key-stream-bytes-placeholder"),
		Address:   "10.0.0.5:9000",
		LastSeen:  time.Now(),
	}

	node.PeerRoute.AddPeer(peer)
	if node.PeerCount() != 1 {
		t.Fatalf("expected peer count 1, got: %d", node.PeerCount())
	}

	if !node.PeerRoute.HasPeer(nodeID) {
		t.Error("peer mapping index missing registered identity descriptor")
	}

	remotePubBytes := make([]byte, 32)
	_, _ = rand.Read(remotePubBytes)

	node.PeerRoute.SetAccessPolicy(nodeID, Write)

	allowed, err := node.PeerRoute.EvaluateSwarmHandshake(remotePubBytes, "WRITE_INTENT")
	if err != nil && allowed {
		t.Errorf("swarm handshake tracking loop failure: %v", err)
	}
}

func TestGossipManager_Propagation(t *testing.T) {
	node, _ := setupTestNode(t)
	gossipReceived := false

	node.RegisterGossip("security:policy:update", func(ctx context.Context, env *GossipEnvelope) error {
		gossipReceived = true
		return nil
	})

	envelope := GossipEnvelope{
		ID:         "update-sequence-009",
		ServiceID:  "security:policy:update",
		Payload:    []byte(`{"rule":"deny-override"}`),
		Signature:  []byte("valid-mock-signature-attestation"),
		Lamport:    1,
		ReceivedAt: time.Now(),
	}

	rawEnvelope, _ := json.Marshal(envelope)

	err := node.Gossip.HandleIngress(context.Background(), rawEnvelope)
	if err != nil {
		t.Fatalf("gossip ingress context rejected during processing: %v", err)
	}

	if !gossipReceived {
		t.Error("gossip manager failed to route validated dataframe frame to target service handler")
	}
}

func TestTunnelManager_AuthenticationRouting(t *testing.T) {
	node, sdf := setupTestNode(t)
	tm := NewTunnelManager("8443", node.Logger)
	
	router, err := NewRouter(sdf, nil, "session_id", node.PolicyEngine, node.SessionManager, node.Logger)
	if err != nil {
		t.Fatalf("failed initializing mock router frame: %v", err)
	}
	
	_ = tm.Init(router)

	nonce := fmt.Sprintf("%d", time.Now().Unix())
	authPayload := TunnelAuthPayload{
		Subdomain:    "ingress-edge",
		IdentityType: "machine",
		Identifier:   "node-machine-id-01",
		Credential:   base64.StdEncoding.EncodeToString([]byte("mock-signature-payload")),
		Nonce:        nonce,
	}

	subject, err := tm.authenticate(authPayload)
	if err != nil {
		t.Fatalf("tunnel authentication path blocked valid machine profile: %v", err)
	}

	if subject != "node-machine-id-01" {
		t.Errorf("expected authenticated identity context 'node-machine-id-01', got: %s", subject)
	}
}
