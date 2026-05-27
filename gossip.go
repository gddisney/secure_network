package secure_network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/flynn/noise"
	"github.com/gddisney/logger"
	"github.com/gddisney/ultimate_db"
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
	Logger    *logger.LogDispatcher // Injected Logger
	clock     uint64
	framePool *sync.Pool
}

func NewGossipManager(db *ultimate_db.DB, router *PeerRoute, sysLog *logger.LogDispatcher) *GossipManager {
	return &GossipManager{
		db:     db,
		router: router,
		Logger: sysLog,
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
		if gm.Logger != nil {
			gm.Logger.Error(fmt.Sprintf("Failed to marshal gossip frame: %v", err))
		}
		return err
	}

	go gm.router.Broadcast(ctx, payload)
	return nil
}

func (gm *GossipManager) HandleIngress(ctx context.Context, encryptedPayload []byte, peerNoiseState *noise.CipherState) error {
	payload, err := peerNoiseState.Decrypt(nil, nil, encryptedPayload)
	if err != nil {
		if gm.Logger != nil {
			gm.Logger.Error("Gossip mesh dropped payload: noise decryption failed")
		}
		return errors.New("gossip: noise payload decryption failed")
	}

	frame := gm.framePool.Get().(*GossipFrame)
	defer gm.framePool.Put(frame)

	if err := json.Unmarshal(payload, frame); err != nil {
		if gm.Logger != nil {
			gm.Logger.Error(fmt.Sprintf("Gossip mesh dropped payload: unmarshal failed: %v", err))
		}
		return err
	}

	authKey := "user:" + string(frame.SignerKey)
	txn := gm.db.BeginTxn()
	_, err = gm.db.Read(AuthPageID, txn, []byte(authKey))
	gm.db.CommitTxn(txn)

	if err != nil {
		if gm.Logger != nil {
			gm.Logger.Audit("system_gossip", "GOSSIP_REJECTED", fmt.Sprintf("Rejected untrusted frame from unverified key: %x", frame.SignerKey[:8]))
		}
		return errors.New("unauthorized gossip origin")
	}

	gm.updateClock(frame.LamportTime)

	writeTxn := gm.db.BeginTxn()
	err = gm.db.Write(AuthPageID, writeTxn, []byte(frame.Key), frame.Value, 0)
	gm.db.CommitTxn(writeTxn)

	if err != nil {
		if gm.Logger != nil {
			gm.Logger.Error(fmt.Sprintf("Gossip state sync DB write failed: %v", err))
		}
		return err
	}

	if gm.Logger != nil {
		gm.Logger.Info(fmt.Sprintf("Synchronized DHT state [%s] at LamportTime %d", frame.Key, frame.LamportTime))
	}
	
	return nil
}
