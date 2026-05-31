package secure_network

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/0TrustCloud/logger"
	"github.com/0TrustCloud/secure_data_format"
)

type GossipEnvelope struct {
	ID         string    `json:"id"`
	ServiceID  string    `json:"service_id"`
	Payload    []byte    `json:"payload"`
	Signature  []byte    `json:"signature"`
	Lamport    uint64    `json:"lamport"`
	Origin     []byte    `json:"origin,omitempty"`
	ReceivedAt time.Time `json:"received_at"`
}

type GossipHandler func(ctx context.Context, env *GossipEnvelope) error

type GossipManager struct {
	peerRoute *PeerRoute
	Logger    *logger.LogDispatcher
	mu        sync.RWMutex
	handlers  map[string]GossipHandler
	seen      map[string]time.Time
	lamport   uint64
}

func NewGossipManager(peerRoute *PeerRoute, sysLog *logger.LogDispatcher) *GossipManager {
	return &GossipManager{
		peerRoute: peerRoute,
		Logger:    sysLog,
		handlers:  make(map[string]GossipHandler),
		seen:      make(map[string]time.Time),
	}
}

func (gm *GossipManager) RegisterHandler(serviceID string, handler GossipHandler) {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	gm.handlers[serviceID] = handler
}

func (gm *GossipManager) Publish(ctx context.Context, serviceID string, payload []byte, signature []byte) error {
	gm.mu.Lock()
	gm.lamport++
	lamport := gm.lamport
	gm.mu.Unlock()

	env := GossipEnvelope{
		ID:         fmt.Sprintf("%s-%d", serviceID, time.Now().UnixNano()),
		ServiceID:  serviceID,
		Payload:    payload,
		Signature:  signature,
		Lamport:    lamport,
		ReceivedAt: time.Now(),
	}

	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}

	if gm.peerRoute == nil {
		return nil
	}

	return gm.peerRoute.Broadcast(ctx, "gossip", raw)
}

func (gm *GossipManager) HandleIngress(ctx context.Context, payload []byte) error {
	var env GossipEnvelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return err
	}

	gm.mu.Lock()
	if ts, exists := gm.seen[env.ID]; exists {
		if time.Since(ts) < time.Hour {
			gm.mu.Unlock()
			return nil
		}
	}

	gm.seen[env.ID] = time.Now()
	if env.Lamport > gm.lamport {
		gm.lamport = env.Lamport
	}
	gm.lamport++
	gm.mu.Unlock()

	if gm.peerRoute != nil && gm.peerRoute.meshNode != nil {
		// Verify signature metrics via dataframe compilation checks
		script := fmt.Sprintf(`gossip:frame(service("%s") lamport(%d))`, env.ServiceID, env.Lamport)
		tx := secure_data_format.DataInvocation{
			TargetAddress: "gossip:ingress:validation",
			Caller:        env.ServiceID,
			Nonce:         env.Lamport,
			Method:        "VERIFY_GOSSIP_ROW",
			Profile:       secure_data_format.ProfileProofOfPoss,
			Args: map[string]interface{}{
				"payload_len": len(env.Payload),
				"signature":   string(env.Signature),
			},
		}
		if _, err := gm.peerRoute.meshNode.SdfEngine.CompileSecureData(script, tx); err != nil {
			return fmt.Errorf("sdf dataframe rejected inbound gossip frame attribution constraints: %w", err)
		}
	}

	gm.mu.RLock()
	handler, ok := gm.handlers[env.ServiceID]
	gm.mu.RUnlock()

	if !ok {
		return nil
	}

	return handler(ctx, &env)
}

func (gm *GossipManager) CleanupSeenCache() {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	cutoff := time.Now().Add(-1 * time.Hour)
	for id, ts := range gm.seen {
		if ts.Before(cutoff) {
			delete(gm.seen, id)
		}
	}
}

func (gm *GossipManager) StartJanitor() {
	ticker := time.NewTicker(15 * time.Minute)
	go func() {
		defer ticker.Stop()
		for range ticker.C {
			gm.CleanupSeenCache()
		}
	}()
}

func (gm *GossipManager) GetLamport() uint64 {
	gm.mu.RLock()
	defer gm.mu.RUnlock()
	return gm.lamport
}

func (gm *GossipManager) SeenCount() int {
	gm.mu.RLock()
	defer gm.mu.RUnlock()
	return len(gm.seen)
}
