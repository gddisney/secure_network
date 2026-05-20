package secure_network

import (
	"context"
	"crypto/tls"
	"log"
	
	"github.com/gddisney/ultimate_db"
	"github.com/gddisney/webauthnext"
)

type EdgeNode struct {
	DB       *ultimate_db.DB
	Router   *Router
	PeerMesh *PeerRoute
	Gossip   *GossipManager
	Gateway  *Gateway
}

func NewEdgeNode(ctx context.Context, dbPath string, staticPrivKey []byte, auth *webauthnext.Provider) (*EdgeNode, error) {
	dm, err := ultimate_db.NewDiskManager(dbPath)
	if err != nil {
		return nil, err
	}
	bp := ultimate_db.NewBufferPool(dm, 1024)
	wal, err := ultimate_db.NewBatchingWAL(dbPath + "_wal.log")
	if err != nil {
		return nil, err
	}
	db := ultimate_db.NewDB(bp, wal)
	ultimate_db.RecoverDB(dbPath+"_wal.log", db)

	peerMesh := NewPeerRoute(db, auth, staticPrivKey)
	gossip := NewGossipManager(db, peerMesh)
	peerMesh.SetIngressHandler(gossip.HandleIngress)

	router, _ := NewRouter(db, nil, "secure_session_token")
	gateway := NewGateway(router, peerMesh)
	peerMesh.SetGateway(gateway)

	return &EdgeNode{
		DB:       db,
		Router:   router,
		PeerMesh: peerMesh,
		Gossip:   gossip,
		Gateway:  gateway,
	}, nil
}

func (n *EdgeNode) Start(port string, tlsConfig *tls.Config) error {
	log.Printf("Starting Zero-Trust Edge Node on port %s", port)
	go n.PeerMesh.Listen(context.Background())
	return n.Gateway.ListenAndServe(port, tlsConfig)
}
