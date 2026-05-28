package secure_network

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
	"github.com/gddisney/logger"
	"github.com/gddisney/service_keys"
	"github.com/gddisney/ultimate_db"
)

const (
	AuthPageID           = 1
	GossipPageID         = 3
	MaxGossipPayloadSize = 1 << 20 // 1MB
	MaxReplayWindow      = 60
)

type GossipFrame struct {
	Key         string `json:"k"`
	Value       []byte `json:"v"`
	LamportTime uint64 `json:"lt"`

	ServiceID string `json:"sid"`
	Timestamp int64  `json:"ts"`

	Signature string `json:"sig"`
}

type GossipManager struct {
	db          *ultimate_db.DB
	router      *PeerRoute
	ServiceKeys *service_keys.ServiceKeyManager
	Logger      *logger.LogDispatcher

	clock uint64

	framePool *sync.Pool
}

func NewGossipManager(
	db *ultimate_db.DB,
	router *PeerRoute,
	serviceKeyMgr *service_keys.ServiceKeyManager,
	sysLog *logger.LogDispatcher,
) *GossipManager {

	return &GossipManager{
		db:          db,
		router:      router,
		ServiceKeys: serviceKeyMgr,
		Logger:      sysLog,

		framePool: &sync.Pool{
			New: func() interface{} {
				return &GossipFrame{}
			},
		},
	}
}

func (gm *GossipManager) Tick() uint64 {
	return atomic.AddUint64(
		&gm.clock,
		1,
	)
}

func (gm *GossipManager) resetFrame(
	frame *GossipFrame,
) {

	frame.Key = ""
	frame.Value = nil
	frame.LamportTime = 0
	frame.ServiceID = ""
	frame.Timestamp = 0
	frame.Signature = ""
}

func (gm *GossipManager) updateClock(
	incomingTime uint64,
) {

	for {

		current := atomic.LoadUint64(
			&gm.clock,
		)

		if current >= incomingTime {
			break
		}

		if atomic.CompareAndSwapUint64(
			&gm.clock,
			current,
			incomingTime,
		) {
			break
		}
	}

	atomic.AddUint64(
		&gm.clock,
		1,
	)
}

func (gm *GossipManager) createSignaturePayload(
	frame *GossipFrame,
) []byte {

	return []byte(
		fmt.Sprintf(
			"%s|%x|%d|%d|%s",
			frame.Key,
			frame.Value,
			frame.LamportTime,
			frame.Timestamp,
			frame.ServiceID,
		),
	)
}

func (gm *GossipManager) BroadcastStateChange(
	ctx context.Context,
	key string,
	value []byte,
	serviceID string,
	signature []byte,
) error {

	if len(value) > MaxGossipPayloadSize {

		return errors.New(
			"payload exceeds gossip limit",
		)
	}

	frame := gm.framePool.Get().(*GossipFrame)
	gm.resetFrame(frame)

	defer func() {

		gm.resetFrame(frame)
		gm.framePool.Put(frame)

	}()

	frame.Key = key
	frame.Value = value
	frame.LamportTime = gm.Tick()
	frame.ServiceID = serviceID
	frame.Timestamp = time.Now().Unix()

	frame.Signature = base64.StdEncoding.EncodeToString(
		signature,
	)

	payload, err := json.Marshal(
		frame,
	)

	if err != nil {

		if gm.Logger != nil {

			gm.Logger.Error(
				fmt.Sprintf(
					"Failed marshaling gossip frame: %v",
					err,
				),
			)
		}

		return err
	}

	if gm.Logger != nil {

		gm.Logger.Debug(
			fmt.Sprintf(
				"Gossip broadcast [%s] from [%s]",
				key,
				serviceID,
			),
		)
	}

	return gm.router.Broadcast(
		ctx,
		payload,
	)
}

func (gm *GossipManager) verifyFrame(
	frame *GossipFrame,
) error {

	if frame.ServiceID == "" {

		return errors.New(
			"missing service identity",
		)
	}

	if frame.Signature == "" {

		return errors.New(
			"missing gossip signature",
		)
	}

	if time.Now().Unix()-frame.Timestamp >
		MaxReplayWindow {

		return errors.New(
			"gossip frame expired",
		)
	}

	signature, err := base64.StdEncoding.DecodeString(
		frame.Signature,
	)

	if err != nil {

		return errors.New(
			"invalid signature encoding",
		)
	}

	payload := gm.createSignaturePayload(
		frame,
	)

	err = gm.ServiceKeys.VerifySignedPayload(
		frame.ServiceID,
		payload,
		signature,
	)

	if err != nil {

		if gm.Logger != nil {

			gm.Logger.Audit(
				frame.ServiceID,
				"GOSSIP_REJECTED",
				fmt.Sprintf(
					"Signature verification failed: %v",
					err,
				),
			)
		}

		return err
	}

	return nil
}

func (gm *GossipManager) HandleIngress(
	ctx context.Context,
	encryptedPayload []byte,
	peerNoiseState *noise.CipherState,
) error {

	payload, err := peerNoiseState.Decrypt(
		nil,
		nil,
		encryptedPayload,
	)

	if err != nil {

		if gm.Logger != nil {

			gm.Logger.Error(
				"Gossip payload decryption failed",
			)
		}

		return errors.New(
			"noise decryption failed",
		)
	}

	if len(payload) > MaxGossipPayloadSize {

		if gm.Logger != nil {

			gm.Logger.Audit(
				"system_gossip",
				"GOSSIP_REJECTED",
				"Payload exceeded maximum size",
			)
		}

		return errors.New(
			"payload exceeds maximum size",
		)
	}

	frame := gm.framePool.Get().(*GossipFrame)
	gm.resetFrame(frame)

	defer func() {

		gm.resetFrame(frame)
		gm.framePool.Put(frame)

	}()

	if err := json.Unmarshal(
		payload,
		frame,
	); err != nil {

		if gm.Logger != nil {

			gm.Logger.Error(
				fmt.Sprintf(
					"Gossip unmarshal failed: %v",
					err,
				),
			)
		}

		return err
	}

	if err := gm.verifyFrame(
		frame,
	); err != nil {

		return err
	}

	gm.updateClock(
		frame.LamportTime,
	)

	writeTxn := gm.db.BeginTxn()

	err = gm.db.Write(
		GossipPageID,
		writeTxn,
		[]byte(frame.Key),
		frame.Value,
		0,
	)

	gm.db.CommitTxn(writeTxn)

	if err != nil {

		if gm.Logger != nil {

			gm.Logger.Error(
				fmt.Sprintf(
					"Gossip DB sync failed: %v",
					err,
				),
			)
		}

		return err
	}

	if gm.Logger != nil {

		gm.Logger.Info(
			fmt.Sprintf(
				"Gossip synchronized [%s] @ Lamport=%d from [%s]",
				frame.Key,
				frame.LamportTime,
				frame.ServiceID,
			),
		)
	}

	return nil
}

func (gm *GossipManager) CurrentLamportTime() uint64 {

	return atomic.LoadUint64(
		&gm.clock,
	)
}
