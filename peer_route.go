package secure_network

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gddisney/logger"
	"github.com/gddisney/service_keys"
)

type AccessPolicy int

const (
	Deny AccessPolicy = iota
	ReadOnly
	See
	Write
	Admin
)

type NodeID [32]byte

type PeerIdentity struct {
	NodeID    NodeID
	PublicKey []byte
	Address   string
	LastSeen  time.Time
}

type PeerMessage struct {
	ID        string    `json:"id"`
	Route     string    `json:"route"`
	Payload   []byte    `json:"payload"`
	Origin    []byte    `json:"origin"`
	Timestamp time.Time `json:"timestamp"`
}

type PeerHandler func(
	ctx context.Context,
	msg *PeerMessage,
) error

type PeerRoute struct {
	meshNode *MeshNode

	serviceKeys *service_keys.ServiceKeyManager

	Logger *logger.LogDispatcher

	mu sync.RWMutex

	handlers map[string]PeerHandler

	accessPolicies map[NodeID]AccessPolicy

	peers map[string]*PeerIdentity
}

func NewPeerRoute(
	node *MeshNode,
	skm *service_keys.ServiceKeyManager,
	sysLog *logger.LogDispatcher,
) *PeerRoute {

	pr := &PeerRoute{
		meshNode:       node,
		serviceKeys:    skm,
		Logger:         sysLog,
		handlers:       make(map[string]PeerHandler),
		accessPolicies: make(map[NodeID]AccessPolicy),
		peers:          make(map[string]*PeerIdentity),
	}

	return pr
}

func (pr *PeerRoute) RegisterHandler(
	route string,
	handler PeerHandler,
) {

	pr.mu.Lock()
	defer pr.mu.Unlock()

	pr.handlers[route] = handler

	if pr.Logger != nil {

		pr.Logger.Debug(
			fmt.Sprintf(
				"PeerRoute handler registered: %s",
				route,
			),
		)
	}
}

func (pr *PeerRoute) Dispatch(
	ctx context.Context,
	msg *PeerMessage,
) error {

	pr.mu.RLock()

	handler, ok := pr.handlers[msg.Route]

	pr.mu.RUnlock()

	if !ok {

		return fmt.Errorf(
			"no handler registered for route: %s",
			msg.Route,
		)
	}

	return handler(
		ctx,
		msg,
	)
}

func (pr *PeerRoute) Broadcast(
	ctx context.Context,
	route string,
	payload []byte,
) error {

	if pr.meshNode == nil {

		return fmt.Errorf(
			"mesh node unavailable",
		)
	}

	hash := sha256.Sum256(
		append(
			[]byte(route),
			payload...,
		),
	)

	msg := PeerMessage{
		ID: hex.EncodeToString(
			hash[:],
		),
		Route:  route,
		Payload: payload,
		Origin: pr.meshNode.noisePub,
		Timestamp: time.Now(),
	}

	raw, err := json.Marshal(
		msg,
	)

	if err != nil {
		return err
	}

	return pr.meshNode.SendAction(
		APIPayload{
			Action: "rpc",
			Content: string(raw),
		},
	)
}

func (pr *PeerRoute) HandleIngress(
	ctx context.Context,
	payload []byte,
) error {

	var msg PeerMessage

	if err := json.Unmarshal(
		payload,
		&msg,
	); err != nil {

		return err
	}

	if pr.Logger != nil {

		pr.Logger.Debug(
			fmt.Sprintf(
				"PeerRoute ingress route=%s",
				msg.Route,
			),
		)
	}

	return pr.Dispatch(
		ctx,
		&msg,
	)
}

func (pr *PeerRoute) AddPeer(
	peer *PeerIdentity,
) {

	pr.mu.Lock()
	defer pr.mu.Unlock()

	key := hex.EncodeToString(
		peer.NodeID[:],
	)

	pr.peers[key] = peer

	if pr.Logger != nil {

		pr.Logger.Info(
			fmt.Sprintf(
				"Peer added: %s",
				key[:12],
			),
		)
	}
}

func (pr *PeerRoute) RemovePeer(
	nodeID NodeID,
) {

	pr.mu.Lock()
	defer pr.mu.Unlock()

	key := hex.EncodeToString(
		nodeID[:],
	)

	delete(
		pr.peers,
		key,
	)

	if pr.Logger != nil {

		pr.Logger.Info(
			fmt.Sprintf(
				"Peer removed: %s",
				key[:12],
			),
		)
	}
}

func (pr *PeerRoute) ListPeers() []*PeerIdentity {

	pr.mu.RLock()
	defer pr.mu.RUnlock()

	out := make(
		[]*PeerIdentity,
		0,
		len(pr.peers),
	)

	for _, peer := range pr.peers {
		out = append(
			out,
			peer,
		)
	}

	return out
}

func (pr *PeerRoute) SetAccessPolicy(
	nodeID NodeID,
	policy AccessPolicy,
) {

	pr.mu.Lock()
	defer pr.mu.Unlock()

	pr.accessPolicies[nodeID] = policy

	if pr.Logger != nil {

		pr.Logger.Debug(
			fmt.Sprintf(
				"Access policy updated for %x -> %d",
				nodeID[:4],
				policy,
			),
		)
	}
}

func (pr *PeerRoute) EvaluateSwarmHandshake(
	remotePub []byte,
	intent string,
) (bool, error) {

	if len(remotePub) < 32 {

		return false,
			fmt.Errorf(
				"invalid remote identity",
			)
	}

	var nodeID NodeID

	copy(
		nodeID[:],
		remotePub[:32],
	)

	pr.mu.RLock()

	policy, ok := pr.accessPolicies[nodeID]

	pr.mu.RUnlock()

	if !ok {

		return false,
			fmt.Errorf(
				"no access policy defined",
			)
	}

	switch policy {

	case Admin:
		return true, nil

	case Write:

		if intent == "WRITE_INTENT" ||
			intent == "READ_INTENT" ||
			intent == "S2P_PULL" {

			return true, nil
		}

	case See:
		return true, nil

	case ReadOnly:

		if intent == "READ_INTENT" ||
			intent == "S2P_PULL" {

			return true, nil
		}

	case Deny:
		return false,
			fmt.Errorf(
				"policy denied",
			)
	}

	return false,
		fmt.Errorf(
			"intent rejected",
		)
}

func (pr *PeerRoute) HasPeer(
	nodeID NodeID,
) bool {

	pr.mu.RLock()
	defer pr.mu.RUnlock()

	key := hex.EncodeToString(
		nodeID[:],
	)

	_, ok := pr.peers[key]

	return ok
}

func (pr *PeerRoute) GetPeer(
	nodeID NodeID,
) (*PeerIdentity, bool) {

	pr.mu.RLock()
	defer pr.mu.RUnlock()

	key := hex.EncodeToString(
		nodeID[:],
	)

	peer, ok := pr.peers[key]

	return peer, ok
}

func (pr *PeerRoute) TouchPeer(
	nodeID NodeID,
) {

	pr.mu.Lock()
	defer pr.mu.Unlock()

	key := hex.EncodeToString(
		nodeID[:],
	)

	if peer, ok := pr.peers[key]; ok {

		peer.LastSeen = time.Now()
	}
}

func (pr *PeerRoute) PeerCount() int {

	pr.mu.RLock()
	defer pr.mu.RUnlock()

	return len(
		pr.peers,
	)
}
