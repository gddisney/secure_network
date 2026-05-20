package secure_network

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"sync"
	"sync/atomic"
	"github.com/gddisney/ultimate_db"
	"github.com/flynn/noise"
)

const AuthPageID = 1

type GossipFrame struct {
	Key         string `json:"k"`
	Value       []byte `json:"v"`
	LamportTime uint64 `json:"lt"`
	SignerKey   []byte `json:"sk"` 
}

type GossipManager struct {
	db        *ultimate_db.DB
	router    *PeerRoute
	clock     uint64
	framePool *sync.Pool
}

func NewGossipManager(db *ultimate_db.DB, router *PeerRoute) *GossipManager {
	return &GossipManager{
		db:     db,
		router: router,
		clock:  0,
		framePool: &sync.Pool{
			New: func() interface{} {
				return &GossipFrame{}
			},
		},
	}
}

func (gm *GossipManager) Tick() uint64 {
	return atomic.AddUint64(&gm.clock, 1)
}

func (gm *GossipManager) updateClock(incomingTime uint64) {
	for {
		current := atomic.LoadUint64(&gm.clock)
		if current >= incomingTime {
			break
		}
		if atomic.CompareAndSwapUint64(&gm.clock, current, incomingTime) {
			break
		}
	}
	atomic.AddUint64(&gm.clock, 1)
}

func (gm *GossipManager) BroadcastStateChange(ctx context.Context, key string, value []byte, signerPublicKey []byte) error {
	frame := gm.framePool.Get().(*GossipFrame)
	defer gm.framePool.Put(frame)

	frame.Key = key
	frame.Value = value
	frame.LamportTime = gm.Tick()
	frame.SignerKey = signerPublicKey

	payload, err := json.Marshal(frame)
	if err != nil {
		return err
	}

	go gm.router.Broadcast(ctx, payload)
	return nil
}

func (gm *GossipManager) HandleIngress(ctx context.Context, encryptedPayload []byte, peerNoiseState *noise.CipherState) error {
	payload, err := peerNoiseState.Decrypt(nil, nil, encryptedPayload)
	if err != nil {
		return errors.New("gossip: noise payload decryption failed")
	}

	frame := gm.framePool.Get().(*GossipFrame)
	defer gm.framePool.Put(frame)

	if err := json.Unmarshal(payload, frame); err != nil {
		return err
	}

	authKey := "user:" + string(frame.SignerKey)
	_, err = gm.db.Read(AuthPageID, gm.db.BeginTxn(), []byte(authKey))
	if err != nil {
		log.Printf("gossip: rejected untrusted frame from unverified key")
		return errors.New("unauthorized gossip origin")
	}

	gm.updateClock(frame.LamportTime)

	err = gm.db.Write(AuthPageID, gm.db.BeginTxn(), []byte(frame.Key), frame.Value, 0)
	if err != nil {
		return err
	}

	log.Printf("gossip: synchronized state %s at LamportTime %d", frame.Key, frame.LamportTime)
	return nil
}
