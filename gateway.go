package secure_network

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
    "crypto/tls"

	"github.com/gddisney/ultimate_db"
	"github.com/flynn/noise"
	"github.com/quic-go/quic-go"
)

type Gateway struct {
	router   *Router
	peerMesh *PeerRoute
	cipher   noise.CipherSuite
	sPriv    []byte
	sPub     []byte
}

func NewGateway(r *Router, peerMesh *PeerRoute) *Gateway {
	return &Gateway{
		router:   r,
		peerMesh: peerMesh,
		cipher:   noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256),
	}
}

func (g *Gateway) SetApplicationHandler(handler http.HandlerFunc) {
	if g.router != nil {
		g.router.Mux.Handle("/", handler)
	}
}

func (g *Gateway) ListenAndServe(port string, tlsConfig *tls.Config) error {
	if g.router != nil {
		g.router.Port = port
		if tlsConfig != nil {
			g.router.TLSConfig = tlsConfig
		}
		g.router.Boot()
	}
	return nil
}

func (g *Gateway) HandleSecureStream(stream quic.Stream) {
	defer stream.Close()

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   g.cipher,
		Random:        nil,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		StaticKeypair: noise.DHKey{Private: g.sPriv, Public: g.sPub},
	})
	if err != nil {
		log.Printf("[GATEWAY] Failed to initialize handshake state: %v", err)
		return
	}

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	if err != nil {
		return
	}

	_, _, _, err = hs.ReadMessage(nil, buf[:n])
	if err != nil {
		log.Printf("[GATEWAY] Handshake failed (Potential Banned User Noise): %v", err)
		return
	}

	remoteKey := hs.PeerStatic()

	if !g.isIdentityValid(remoteKey) {
		log.Printf("[GATEWAY] Revoked key attempted connection. Dropping stream.")
		return
	}

	respMsg, _, csRecv, err := hs.WriteMessage(nil, nil)
	if err != nil {
		log.Printf("[GATEWAY] Failed to complete handshake: %v", err)
		return
	}
	
	_, err = stream.Write(respMsg)
	if err != nil {
		return
	}

	log.Printf("[GATEWAY] Secure Tunnel established for identity: %x", remoteKey[:8])

	for {
		n, err := stream.Read(buf)
		if err != nil {
			break
		}

		decrypted, err := csRecv.Decrypt(nil, nil, buf[:n])
		if err != nil {
			continue
		}

		g.routeToAPI(remoteKey, decrypted)
	}
}

func (g *Gateway) isIdentityValid(pubKey []byte) bool {
	_, err := g.router.DB.Read(1, g.router.DB.BeginTxn(), pubKey)
	return err == nil
}

func (g *Gateway) ScrubbingCycle() {
	ticker := time.NewTicker(24 * time.Hour)
	for range ticker.C {
		log.Println("[CLEANUP] Starting global revocation scrub...")
		
		if g.router.GUIKit == nil {
			continue
		}

		tree := ultimate_db.NewBTree(g.router.GUIKit.BP, 2)
		cursor, _ := ultimate_db.NewBTreeCursor(tree)
		
		for {
			key, val, err := cursor.Next()
			if err != nil {
				break
			}

			var meta struct { Signer []byte }
			json.Unmarshal(val, &meta)

			if len(meta.Signer) > 0 && !g.isIdentityValid(meta.Signer) {
				g.router.DB.Write(2, g.router.DB.BeginTxn(), key, nil, time.Nanosecond)
				log.Printf("[CLEANUP] Revoked data for identity: %x", meta.Signer[:8])
			}
		}
		cursor.Close()
	}
}

type APIPayload struct {
	Action  string `json:"action"`
	Content string `json:"content,omitempty"`
	Target  string `json:"target,omitempty"`
	Value   int    `json:"value,omitempty"`
}

type ContentMeta struct {
	Signer    []byte `json:"signer"`
	Content   string `json:"content,omitempty"`
	Target    string `json:"target,omitempty"`
	Value     int    `json:"value,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

func (g *Gateway) routeToAPI(signer []byte, payload []byte) {
	var req APIPayload
	if err := json.Unmarshal(payload, &req); err != nil {
		log.Printf("[GATEWAY] Invalid API payload from %x: %v", signer[:8], err)
		return
	}

	txnID := g.router.DB.BeginTxn()
	now := time.Now().Unix()

	switch req.Action {
	case "post":
		postID := fmt.Sprintf("post:%d:%x", time.Now().UnixNano(), signer[:4])
		meta := ContentMeta{
			Signer:    signer,
			Content:   req.Content,
			CreatedAt: now,
		}
		val, _ := json.Marshal(meta)
		err := g.router.DB.Write(2, txnID, []byte(postID), val, 0)
		if err != nil {
			log.Printf("[GATEWAY] DB Write Failed (Post): %v", err)
			return
		}
		log.Printf("[GATEWAY] Post created by %x: %s", signer[:8], postID)

	case "karma":
		if req.Target == "" {
			return
		}
		karmaKey := fmt.Sprintf("karma:%s:%x", req.Target, signer[:8])
		meta := ContentMeta{
			Signer:    signer,
			Target:    req.Target,
			Value:     req.Value,
			CreatedAt: now,
		}
		val, _ := json.Marshal(meta)
		err := g.router.DB.Write(3, txnID, []byte(karmaKey), val, 0)
		if err == nil {
			log.Printf("[GATEWAY] Karma (%d) applied to %s by %x", req.Value, req.Target, signer[:8])
		}

	case "share":
		if req.Target == "" {
			return
		}
		shareKey := fmt.Sprintf("share:%s:%x", req.Target, signer[:8])
		meta := ContentMeta{
			Signer:    signer,
			Target:    req.Target,
			CreatedAt: now,
		}
		val, _ := json.Marshal(meta)
		err := g.router.DB.Write(3, txnID, []byte(shareKey), val, 0)
		if err == nil {
			log.Printf("[GATEWAY] Content %s shared by %x", req.Target, signer[:8])
		}

	default:
		log.Printf("[GATEWAY] Unknown action '%s' from %x", req.Action, signer[:8])
	}
}
