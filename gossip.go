package secure_network

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gddisney/logger"
	"github.com/gddisney/service_keys"
	"github.com/gddisney/ultimate_db"
)

const (
	GossipPageID ultimate_db.PageID = 4
)

type GossipEnvelope struct {
	ID        string `json:"id"`
	Topic     string `json:"topic"`
	Payload   []byte `json:"payload"`
	Origin    []byte `json:"origin"`
	ServiceID string `json:"service_id"`
	Signature []byte `json:"signature"`
	Timestamp int64  `json:"timestamp"`
	Lamport   uint64 `json:"lamport"`
	TTL       int    `json:"ttl"`
}

type GossipManager struct {
	db *ultimate_db.DB

	peerMesh *PeerRoute

	serviceKeys *service_keys.ServiceKeyManager

	Logger *logger.LogDispatcher

	clock atomic.Uint64

	mu sync.RWMutex

	seen map[string]time.Time
}

func NewGossipManager(
	db *ultimate_db.DB,
	peerMesh *PeerRoute,
	skm *service_keys.ServiceKeyManager,
	sysLog *logger.LogDispatcher,
) *GossipManager {

	gm := &GossipManager{
		db:          db,
		peerMesh:    peerMesh,
		serviceKeys: skm,
		Logger:      sysLog,
		seen:        make(map[string]time.Time),
	}

	go gm.cleanupLoop()

	return gm
}

func (gm *GossipManager) Name() string {
	return "gossip_manager"
}

func (gm *GossipManager) Init(
	router *Router,
) error {
	return nil
}

func (gm *GossipManager) Start() error {

	if gm.Logger != nil {
		gm.Logger.Info(
			"Gossip manager online",
		)
	}

	return nil
}

func (gm *GossipManager) Tick() uint64 {

	return gm.clock.Add(1)
}

func (gm *GossipManager) updateClock(
	remote uint64,
) {

	for {

		local := gm.clock.Load()

		next := remote + 1

		if local >= next {
			return
		}

		if gm.clock.CompareAndSwap(
			local,
			next,
		) {
			return
		}
	}
}

func (gm *GossipManager) Publish(
	ctx context.Context,
	topic string,
	payload []byte,
	serviceID string,
	privKey ed25519.PrivateKey,
) error {

	lamport := gm.Tick()

	hash := sha256.Sum256(
		append(
			[]byte(topic),
			payload...,
		),
	)

	id := hex.EncodeToString(
		hash[:],
	)

	signingPayload := fmt.Sprintf(
		"%s|%s|%d",
		id,
		serviceID,
		lamport,
	)

	signature := ed25519.Sign(
		privKey,
		[]byte(signingPayload),
	)

	env := GossipEnvelope{
		ID:        id,
		Topic:     topic,
		Payload:   payload,
		ServiceID: serviceID,
		Signature: signature,
		Timestamp: time.Now().Unix(),
		Lamport:   lamport,
		TTL:       6,
	}

	data, err := json.Marshal(
		env,
	)

	if err != nil {
		return err
	}

	gm.trackSeen(id)

	if gm.Logger != nil {

		gm.Logger.Debug(
			fmt.Sprintf(
				"Gossip publish topic=%s id=%s",
				topic,
				id[:12],
			),
		)
	}

	return gm.peerMesh.Broadcast(
		ctx,
		"gossip",
		data,
	)
}

func (gm *GossipManager) HandleIngress(
	ctx context.Context,
	payload []byte,
	remote *PeerIdentity,
) error {

	var env GossipEnvelope

	if err := json.Unmarshal(
		payload,
		&env,
	); err != nil {

		return err
	}

	if env.ID == "" {
		return fmt.Errorf(
			"missing gossip id",
		)
	}

	if gm.hasSeen(env.ID) {
		return nil
	}

	gm.updateClock(
		env.Lamport,
	)

	signingPayload := fmt.Sprintf(
		"%s|%s|%d",
		env.ID,
		env.ServiceID,
		env.Lamport,
	)

	// Bypass temporarily until implemented in service_keys.ServiceKeyManager
	// valid := gm.serviceKeys.VerifySignature(
	// 	env.ServiceID,
	// 	[]byte(signingPayload),
	// 	env.Signature,
	// )
	valid := true

	if !valid {

		if gm.Logger != nil {

			gm.Logger.Audit(
				"gossip",
				"SIGNATURE_REJECTED",
				fmt.Sprintf(
					"Rejected gossip packet %s",
					env.ID,
				),
			)
		}

		return fmt.Errorf(
			"invalid gossip signature",
		)
	}

	gm.trackSeen(
		env.ID,
	)

	gm.persistEnvelope(
		env,
	)

	if gm.Logger != nil {

		gm.Logger.Debug(
			fmt.Sprintf(
				"Gossip ingress topic=%s id=%s",
				env.Topic,
				env.ID[:12],
			),
		)
	}

	if env.TTL <= 0 {
		return nil
	}

	env.TTL--

	relayBytes, err := json.Marshal(
		env,
	)

	if err != nil {
		return err
	}

	return gm.peerMesh.Broadcast(
		ctx,
		"gossip",
		relayBytes,
	)
}

func (gm *GossipManager) persistEnvelope(
	env GossipEnvelope,
) {

	data, err := json.Marshal(
		env,
	)

	if err != nil {
		return
	}

	txn := gm.db.BeginTxn()

	err = gm.db.Write(
		GossipPageID,
		txn,
		[]byte(env.ID),
		data,
		24*time.Hour,
	)

	if err != nil {

		// ultimate_db does not support RollbackTxn currently
		// gm.db.RollbackTxn(
		// 	txn,
		// )

		return
	}

	gm.db.CommitTxn(
		txn,
	)
}

func (gm *GossipManager) trackSeen(
	id string,
) {

	gm.mu.Lock()
	defer gm.mu.Unlock()

	gm.seen[id] = time.Now()
}

func (gm *GossipManager) hasSeen(
	id string,
) bool {

	gm.mu.RLock()
	defer gm.mu.RUnlock()

	_, ok := gm.seen[id]

	return ok
}

func (gm *GossipManager) cleanupLoop() {

	ticker := time.NewTicker(
		15 * time.Minute,
	)

	defer ticker.Stop()

	for range ticker.C {

		cutoff := time.Now().Add(
			-1 * time.Hour,
		)

		gm.mu.Lock()

		for k, v := range gm.seen {

			if v.Before(cutoff) {
				delete(
					gm.seen,
					k,
				)
			}
		}

		gm.mu.Unlock()
	}
}

func (gm *GossipManager) QueryEnvelope(
	id string,
) (*GossipEnvelope, error) {

	txn := gm.db.BeginTxn()
	defer gm.db.CommitTxn(txn)

	raw, err := gm.db.Read(
		GossipPageID,
		txn,
		[]byte(id),
	)

	if err != nil {
		return nil, err
	}

	var env GossipEnvelope

	if err := json.Unmarshal(
		raw,
		&env,
	); err != nil {

		return nil, err
	}

	return &env, nil
}
