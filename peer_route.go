package secure_network

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/flynn/noise"
	"github.com/gddisney/logger"
	"github.com/gddisney/ultimate_db"
	"github.com/gddisney/webauthnext"
)

const (
	SystemPageID ultimate_db.PageID = 1
	CachePageID  ultimate_db.PageID = 2
)

type AccessLevel int

const (
	Reject AccessLevel = iota
	ReadOnly
	See
)

type NodeID [32]byte

type SwarmObject struct {
	ObjectID  NodeID    `json:"object_id"`
	OwnerID   NodeID    `json:"owner_id"`
	Payload   []byte    `json:"payload"`
	Signature []byte    `json:"signature"`
	CreatedAt time.Time `json:"created_at"`
}

type RoutingEntry struct {
	ID        NodeID    `json:"id"`
	Address   string    `json:"address"`
	UpdatedAt time.Time `json:"updated_at"`
}

type IngressHandler func(
	context.Context,
	[]byte,
	*noise.CipherState,
) error

type PeerRoute struct {
	db             *ultimate_db.DB
	gateway        *Gateway
	auth           *webauthnext.Provider
	localID        NodeID
	ingressHandler IngressHandler

	policies   map[NodeID]AccessLevel
	policiesMu sync.RWMutex

	Logger *logger.LogDispatcher
}

func NewPeerRoute(
	db *ultimate_db.DB,
	auth *webauthnext.Provider,
	hardwareKey []byte,
	sysLog *logger.LogDispatcher,
) *PeerRoute {

	localHash := sha256.Sum256(hardwareKey)

	return &PeerRoute{
		db:       db,
		auth:     auth,
		localID:  localHash,
		policies: make(map[NodeID]AccessLevel),
		Logger:   sysLog,
	}
}

func (p *PeerRoute) SetGateway(g *Gateway) {
	p.gateway = g
}

func (p *PeerRoute) SetIngressHandler(
	handler IngressHandler,
) {
	p.ingressHandler = handler
}

func (p *PeerRoute) Listen(
	ctx context.Context,
) {

	if p.Logger != nil {
		p.Logger.Info(
			"PeerRoute listener active",
		)
	}

	<-ctx.Done()

	if p.Logger != nil {
		p.Logger.Info(
			"PeerRoute listener shutting down",
		)
	}
}

func (p *PeerRoute) Broadcast(
	ctx context.Context,
	payload []byte,
) {

	if p.Logger != nil {

		p.Logger.Debug(
			fmt.Sprintf(
				"Broadcasting payload (%d bytes)",
				len(payload),
			),
		)
	}

	if p.gateway != nil {

		if broadcaster, ok := any(p.gateway).(interface {
			Broadcast(context.Context, []byte) error
		}); ok {

			if err := broadcaster.Broadcast(
				ctx,
				payload,
			); err != nil {

				if p.Logger != nil {

					p.Logger.Error(
						fmt.Sprintf(
							"Broadcast failed: %v",
							err,
						),
					)
				}
			}
		}
	}
}

func (p *PeerRoute) SetAccessPolicy(
	remoteID NodeID,
	level AccessLevel,
) {

	p.policiesMu.Lock()
	defer p.policiesMu.Unlock()

	p.policies[remoteID] = level

	if p.Logger != nil {

		p.Logger.Audit(
			fmt.Sprintf("%x", remoteID[:8]),
			"ACCESS_POLICY_UPDATED",
			fmt.Sprintf(
				"Policy set to level %d",
				level,
			),
		)
	}
}

func (p *PeerRoute) EvaluateSwarmHandshake(
	remoteIdentity []byte,
	intent string,
) (bool, error) {

	var remoteID NodeID
	copy(remoteID[:], remoteIdentity)

	p.policiesMu.RLock()
	level, exists := p.policies[remoteID]
	p.policiesMu.RUnlock()

	if !exists {

		if p.Logger != nil {

			p.Logger.Audit(
				fmt.Sprintf("%x", remoteIdentity[:8]),
				"HANDSHAKE_REJECTED",
				"No access policy established",
			)
		}

		return false, errors.New(
			"connection rejected: no access policy established",
		)
	}

	switch level {

	case Reject:

		if p.Logger != nil {

			p.Logger.Audit(
				fmt.Sprintf("%x", remoteIdentity[:8]),
				"HANDSHAKE_REJECTED",
				"Peer explicitly rejected",
			)
		}

		return false, errors.New(
			"connection rejected by policy",
		)

	case ReadOnly:

		if intent != "S2P_PULL" {

			if p.Logger != nil {

				p.Logger.Audit(
					fmt.Sprintf("%x", remoteIdentity[:8]),
					"HANDSHAKE_REJECTED",
					"Read-only policy enforced",
				)
			}

			return false, errors.New(
				"read-only access enforced",
			)
		}

		return true, nil

	case See:
		return true, nil

	default:
		return false, errors.New(
			"unknown access level",
		)
	}
}

func (p *PeerRoute) PublishToSwarm(
	ctx context.Context,
	payload []byte,
) (NodeID, error) {

	hash := sha256.Sum256(payload)

	var objID NodeID
	copy(objID[:], hash[:])

	signature := p.auth.SignPayload(payload)

	obj := SwarmObject{
		ObjectID:  objID,
		OwnerID:   p.localID,
		Payload:   payload,
		Signature: signature,
		CreatedAt: time.Now(),
	}

	objBytes, err := json.Marshal(obj)
	if err != nil {
		return objID, err
	}

	txn := p.db.BeginTxn()
	defer p.db.CommitTxn(txn)

	err = p.db.Write(
		CachePageID,
		txn,
		objID[:],
		objBytes,
		72*time.Hour,
	)

	if err != nil {

		if p.Logger != nil {

			p.Logger.Error(
				fmt.Sprintf(
					"Failed swarm publish: %v",
					err,
				),
			)
		}

		return objID, err
	}

	if p.Logger != nil {

		p.Logger.Info(
			fmt.Sprintf(
				"Published object %x to swarm cache",
				objID[:8],
			),
		)
	}

	go p.Broadcast(ctx, payload)

	return objID, nil
}

func (p *PeerRoute) PullFromSwarm(
	ctx context.Context,
	objID NodeID,
) ([]byte, error) {

	txn := p.db.BeginTxn()
	defer p.db.CommitTxn(txn)

	valBytes, err := p.db.Read(
		CachePageID,
		txn,
		objID[:],
	)

	if err != nil {
		return nil, err
	}

	if valBytes == nil {
		return nil, errors.New(
			"object not found",
		)
	}

	var obj SwarmObject

	if err := json.Unmarshal(
		valBytes,
		&obj,
	); err != nil {

		return nil, err
	}

	if p.Logger != nil {

		p.Logger.Debug(
			fmt.Sprintf(
				"Pulled object %x from swarm cache",
				objID[:8],
			),
		)
	}

	return obj.Payload, nil
}

func (p *PeerRoute) RevokeObject(
	ctx context.Context,
	objID NodeID,
) error {

	txn := p.db.BeginTxn()
	defer p.db.CommitTxn(txn)

	err := p.db.Write(
		CachePageID,
		txn,
		objID[:],
		[]byte{},
		time.Nanosecond,
	)

	if err != nil {

		if p.Logger != nil {

			p.Logger.Error(
				fmt.Sprintf(
					"Failed object revoke: %v",
					err,
				),
			)
		}

		return err
	}

	if p.Logger != nil {

		p.Logger.Info(
			fmt.Sprintf(
				"Revoked object %x from swarm cache",
				objID[:8],
			),
		)
	}

	return nil
}

func (p *PeerRoute) FindClosestNodes(
	targetID NodeID,
	count int,
) ([]RoutingEntry, error) {

	txn := p.db.BeginTxn()
	defer p.db.CommitTxn(txn)

	prefix := []byte("dht_node:")

	closest := make([]RoutingEntry, 0)

	err := p.db.Scan(
		SystemPageID,
		txn,
		prefix,

		func(key, value []byte) bool {

			var entry RoutingEntry

			if err := json.Unmarshal(
				value,
				&entry,
			); err == nil {

				closest = append(
					closest,
					entry,
				)
			}

			return true
		},
	)

	if err != nil {
		return nil, err
	}

	sort.Slice(
		closest,
		func(i, j int) bool {

			distI := xorDistance(
				closest[i].ID,
				targetID,
			)

			distJ := xorDistance(
				closest[j].ID,
				targetID,
			)

			return bytes.Compare(
				distI[:],
				distJ[:],
			) < 0
		},
	)

	if len(closest) > count {
		closest = closest[:count]
	}

	if p.Logger != nil {

		p.Logger.Debug(
			fmt.Sprintf(
				"Located %d closest nodes",
				len(closest),
			),
		)
	}

	return closest, nil
}

func (p *PeerRoute) UpdateRoutingTable(
	remoteID NodeID,
	address string,
	dbscProof []byte,
) error {

	isValid, err := p.auth.VerifyAddressClaim(
		remoteID[:],
		address,
		dbscProof,
	)

	if err != nil || !isValid {

		if p.Logger != nil {

			p.Logger.Audit(
				fmt.Sprintf("%x", remoteID[:8]),
				"ROUTING_REJECTED",
				"Hardware verification failed",
			)
		}

		return errors.New(
			"hardware verification failed",
		)
	}

	entry := RoutingEntry{
		ID:        remoteID,
		Address:   address,
		UpdatedAt: time.Now(),
	}

	valBytes, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	key := append(
		[]byte("dht_node:"),
		remoteID[:]...,
	)

	txn := p.db.BeginTxn()
	defer p.db.CommitTxn(txn)

	err = p.db.Write(
		SystemPageID,
		txn,
		key,
		valBytes,
		2*time.Hour,
	)

	if err != nil {

		if p.Logger != nil {

			p.Logger.Error(
				fmt.Sprintf(
					"Failed routing update: %v",
					err,
				),
			)
		}

		return err
	}

	if p.Logger != nil {

		p.Logger.Info(
			fmt.Sprintf(
				"Routing updated for node %x (%s)",
				remoteID[:8],
				address,
			),
		)
	}

	return nil
}

func xorDistance(
	a,
	b NodeID,
) NodeID {

	var result NodeID

	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}

	return result
}
