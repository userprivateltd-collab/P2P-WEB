# ⚡ AirDrop Web (P2P Transfer with E2EE)

AirDrop Web is a lightweight, zero-server peer-to-peer (P2P) file transfer application. Built with **Vanilla JavaScript**, **WebRTC**, and **PeerJS**, it allows direct device-to-device file streaming straight from the browser.

Beyond WebRTC's default transit security, AirDrop Web implements **Application-Layer End-to-End Encryption (E2EE)** using the native **Web Crypto API**. Payload chunks are encrypted on the sender's device before reaching the wire and decrypted only on the receiver's device.

Designed with a modern dark-mode aesthetic featuring glassmorphism elements and ambient liquid animations, it deploys effortlessly as a static site on platforms like **Vercel**.

---

## ✨ Features

- 🔐 **Application-Layer E2EE:** Custom zero-dependency encryption using native browser **Web Crypto API** (ECDH key exchange + AES-GCM chunk encryption).
- 🚀 **True Peer-to-Peer:** Files stream chunk-by-chunk (16KB buffers) directly from sender to receiver without touching a storage server.
- 🔑 **Ephemeral Key Exchange:** ECDH key pair generated per session; shared secret derived on the fly and never transmitted over the network.
- ⚡ **Zero-Server Storage:** No backend storage, database, or custom signaling server required.
- 📱 **Cross-Platform:** Works on any modern web browser (desktop or mobile) supporting WebRTC and Web Crypto API.
- 🎨 **Minimalist Glassmorphism UI:** Clean dark aesthetic powered by Google Inter typography and subtle CSS animations.

---

## 🛠️ Tech Stack

- **Frontend:** Vanilla HTML5, CSS3, JavaScript (ES6+)
- **Security & Cryptography:** Native Web Crypto API (`window.crypto.subtle` for ECDH & AES-GCM)
- **P2P & WebRTC:** [PeerJS](https://peerjs.com/) (Abstracts WebRTC signaling using PeerJS public cloud server)
- **Deployment:** [Vercel](https://vercel.com) (`vercel.json` static configuration)

---

## 🔒 Security Architecture (E2EE Pipeline)
