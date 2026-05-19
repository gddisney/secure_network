# secure_network

`secure_network` is a high-performance, zero-trust edge ingress network and microkernel router written in Go. It enforces hardware-backed session integrity at the HTTP layer using **Device Bound Session Credentials (DBSC)** over dual-stack HTTP/3, and orchestrates an encrypted backplane using the **Noise Protocol (IK Handshake)** over QUIC streams.

## Features

* **Dual-Stack Ingress Edge**: Simultaneous HTTP/3 (UDP) and HTTPS (TCP fallback) routing on a single port via `quic-go`.
* **Native DBSC Interception**: Response-wrapping middleware that automatically handles browser-level hardware key registration requests (`Secure-Session-Registration`) and session check-ins.
* **Cryptographic Ingress Gateway**: Asynchronous mesh communication via the Noise Protocol (`noise.HandshakeIK`), dynamically authenticating remote nodes against your active user directory.
* **Connection Hijacking Support**: Native proxying capabilities for full-duplex persistent streams like WebSockets directly through authenticated QUIC tunnels.
* **Automated State Revocation**: Background B-Tree scrubbing that sweeps data pages every 24 hours to instantly invalidate and purge data belonging to revoked or banned identities.

---

## Architectural Layout

```
         [ Public Traffic ]
                 │
      ┌──────────┴──────────┐
      ▼                     ▼
 HTTP/3 (UDP)          HTTPS (TCP)
  (Port 443)            (Port 443)
      │                     │
      └──────────┬──────────┘
                 ▼
       [ dbscInterceptor ]  ◄── Enforces Hardware Binding
                 │
        ┌────────┴────────┐
        ▼                 ▼
 ┌─────────────┐   ┌─────────────┐
 │ QUIC Tunnel │   │ GUIKit Mux  │
 └─────────────┘   └─────────────┘
        │
        ▼
 [ NoiseGateway ]  ◄── Validates Static Public Key on Page 1

```

---

## Core Infrastructure Dependencies

This repository serves as the central networking hub for your infrastructure, relying on the following decoupled components:

* **`github.com/gddisney/ultimate_db`**: Embedded, transactional database providing buffer pool management and multi-page transactional boundaries.
* **`github.com/gddisney/guikit`**: UI engine and core HTTP state handler.
* **`github.com/gddisney/webauthnext`** *(Optional Co-process)*: Passkey OIDC Identity Provider handling upstream authentication loops when DBSC challenges fail.

---

## Technical Specifications

### DBSC State Machine

The `dbscInterceptor` actively monitors inbound headers matching your `TargetCookie`.

1. **Registration**: When a cookie is created or validated without a hardware binding, the edge injects a `Secure-Session-Registration` header pointing the browser to `/StartSession`.
2. **Challenge/Response**: Client check-ins at `/RefreshEndpoint` must present a valid `Secure-Session-Response`. Missing or stale cryptographic context triggers a `Secure-Session-Challenge` and drops unauthenticated traffic straight back to the login loop.

### Noise Gateway Layout

The asynchronous tunnel handles zero-trust commands by parsing a dedicated JSON protocol. Authorized keys are stored in Page 1, while user actions are written downstream:

* **Page 1 (`AuthPageID`)**: Active user/device identities keyed by their Noise static public key.
* **Page 2**: Public text content and posts (`post:{timestamp}:{signer_prefix}`).
* **Page 3**: Network interactions, shares, and telemetry tracking (`karma:` / `share:`).

---

## Getting Started

### Installation

Initialize the module and pull down the detached core packages:

```bash
go get github.com/gddisney/secure_network
go get github.com/gddisney/ultimate_db@main
go get github.com/gddisney/guikit@main

```

### Basic Initialization

Integrate the router into your system execution sequence:

```go
package main

import (
	"log"
	"github.com/gddisney/secure_network/router"
	"github.com/gddisney/secure_network/gateway"
)

func main() {
	// Initialize the dual-stack microkernel router
	r, err := router.NewRouter(
		"443", 
		"/var/data/app.db", 
		"/var/data/wal.log", 
		"secure_session_token",
	)
	if err != nil {
		log.Fatalf("Kernel initialization failed: %v", err)
	}

	// Instantiate and attach your backend Noise gateway
	nwGateway := gateway.NewNoiseGateway(r)
	
	// Start background data remediation routines
	go nwGateway.ScrubbingCycle()

	// Boot up internal daemons and listen on edge sockets
	r.Boot()
}

```
