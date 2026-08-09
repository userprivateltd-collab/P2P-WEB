const CHUNK_SIZE = 4096; // 4KB chunk size to guarantee safe delivery over strict WebRTC TURN relays and smaller MTUs

// DOM Elements
const roomSection = document.getElementById('room-section');
const transferSection = document.getElementById('transfer-section');
const roomInput = document.getElementById('room-input');
const joinBtn = document.getElementById('join-btn');
const roomStatus = document.getElementById('room-status');

const fileInput = document.getElementById('file-input');
const uploadArea = document.getElementById('upload-area');
const selectedFileName = document.getElementById('selected-file-name');
const sendBtn = document.getElementById('send-btn');
const sendAnotherBtn = document.getElementById('send-another-btn');
const downloadList = document.getElementById('download-list');
const downloadStatusText = document.getElementById('download-status-text');

const createBtn = document.getElementById('create-btn');
const createdCodeContainer = document.getElementById('created-code-container');
const generatedCodeSpan = document.getElementById('generated-code');
const copyBtn = document.getElementById('copy-btn');

const progressContainer = document.getElementById('progress-container');
const progressText = document.getElementById('progress-text');
const progressBar = document.getElementById('progress-bar');
const progressPercentage = document.getElementById('progress-percentage');
const downloadContainer = document.getElementById('download-container');

let peer = null;
let dataConnection = null;
let filesToTransfer = [];

// E2EE State
let myKeyPair = null;
let sharedCryptoKey = null;
let localE2EEReady = false;
let remoteE2EEReady = false;
let handshakeResolve = null;
let handshakePromise = null;

function resetHandshakeGate() {
    localE2EEReady = false;
    remoteE2EEReady = false;
    sharedCryptoKey = null;
    handshakePromise = new Promise(resolve => { handshakeResolve = resolve; });
}

// File Receiving state
let incomingFileInfo = null;
let incomingFileData = [];
let receivedSize = 0;
let decryptionQueue = Promise.resolve();
let expectedChunks = 0;  // DEBUG: total chunks sender will send
let receivedChunks = 0; // DEBUG: how many chunks receiver has decrypted

const APP_PREFIX = 'airdrop-web-p2p-';

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// --- Crypto Functions ---

async function generateECDHKeyPair() {
    return await window.crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveKey']
    );
}

async function exportPublicKey(key) {
    return await window.crypto.subtle.exportKey('jwk', key);
}

async function importPublicKey(jwk) {
    return await window.crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        []
    );
}

async function deriveAESKey(privateKey, publicKey) {
    return await window.crypto.subtle.deriveKey(
        { name: 'ECDH', public: publicKey },
        privateKey,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
}

async function startE2EEHandshake() {
    resetHandshakeGate();
    myKeyPair = await generateECDHKeyPair();
    console.log('[HANDSHAKE] Local key generated');
    const pubJwk = await exportPublicKey(myKeyPair.publicKey);
    dataConnection.send(JSON.stringify({
        type: 'ecdh-public-key',
        key: pubJwk
    }));
    console.log('[HANDSHAKE] Public key sent');
}

// =========================================================================
// CENTRALIZED ICE / STUN / TURN CONFIGURATION
// Fill in your TURN server details below to enable mobile-to-mobile and
// mobile-to-laptop connections across cellular / Symmetric NAT firewalls.
// =========================================================================
const TURN_CONFIG = {
    // Specify your TURN URLs (UDP, TCP, TLS) as a string or array:
    // e.g. [
    //     "turn:your-turn-server.com:3478?transport=udp",
    //     "turn:your-turn-server.com:3478?transport=tcp",
    //     "turns:your-turn-server.com:443?transport=tcp"
    // ]
    urls: [],
    username: "",   // e.g. "your-username"
    credential: ""  // e.g. "your-password"
};

function getIceServers() {
    const servers = [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' },
        { urls: 'stun:stun3.l.google.com:19302' },
        { urls: 'stun:stun4.l.google.com:19302' },
        { urls: 'stun:stun.cloudflare.com:3478' }
    ];

    if (TURN_CONFIG.urls && (Array.isArray(TURN_CONFIG.urls) ? TURN_CONFIG.urls.length > 0 : TURN_CONFIG.urls) && TURN_CONFIG.username && TURN_CONFIG.credential) {
        servers.push({
            urls: TURN_CONFIG.urls,
            username: TURN_CONFIG.username,
            credential: TURN_CONFIG.credential
        });
    }

    return servers;
}

const peerConfig = {
    config: {
        iceServers: getIceServers(),
        iceTransportPolicy: 'all',
        iceCandidatePoolSize: 10
    }
};

function setupPeerConnectionLogging(conn) {
    console.log('[NET] Peer connection created');

    const checkPC = setInterval(() => {
        const pc = conn.peerConnection || conn._peerConnection;
        if (pc) {
            clearInterval(checkPC);

            console.log(`[WEBRTC] connectionState=${pc.connectionState || 'new'}`);
            console.log(`[WEBRTC] iceConnectionState=${pc.iceConnectionState || 'new'}`);
            console.log(`[WEBRTC] iceGatheringState=${pc.iceGatheringState || 'new'}`);
            console.log(`[WEBRTC] signalingState=${pc.signalingState || 'stable'}`);

            pc.addEventListener('icecandidate', (event) => {
                if (event.candidate) {
                    const cand = event.candidate.candidate;
                    let type = 'unknown';
                    if (cand.includes('typ host')) type = 'host';
                    else if (cand.includes('typ srflx')) type = 'srflx (STUN)';
                    else if (cand.includes('typ relay')) type = 'relay (TURN)';
                    console.log(`[ICE CANDIDATE] type=${type} -> ${cand}`);
                }
            });

            pc.addEventListener('icecandidateerror', (event) => {
                console.error(`[ICE ERROR] code=${event.errorCode} url=${event.url} text=${event.errorText}`);
            });

            pc.addEventListener('iceconnectionstatechange', () => {
                const state = pc.iceConnectionState;
                console.log(`[ICE] ${state}`);
                console.log(`[WEBRTC] iceConnectionState=${state}`);
                if (state === 'connected' || state === 'completed') {
                    checkE2EEComplete();
                }
            });

            pc.addEventListener('connectionstatechange', () => {
                console.log(`[WEBRTC] connectionState=${pc.connectionState}`);
            });

            pc.addEventListener('icegatheringstatechange', () => {
                console.log(`[ICE] ${pc.iceGatheringState}`);
                console.log(`[WEBRTC] iceGatheringState=${pc.iceGatheringState}`);
            });

            pc.addEventListener('signalingstatechange', () => {
                console.log(`[WEBRTC] signalingState=${pc.signalingState}`);
            });
        }
    }, 50);

    setTimeout(() => clearInterval(checkPC), 15000);
}

function checkE2EEComplete() {
    const pc = dataConnection ? (dataConnection.peerConnection || dataConnection._peerConnection) : null;
    const iceState = pc ? pc.iceConnectionState : 'unknown';
    const isIceConnected = !pc || iceState === 'connected' || iceState === 'completed' || iceState === 'new';

    if (sharedCryptoKey && localE2EEReady && remoteE2EEReady && dataConnection && dataConnection.open && isIceConnected) {
        console.log('[HANDSHAKE] E2EE COMPLETE');
        roomStatus.innerText = 'Connected & E2EE Secured';
        const connStatusEl = document.querySelector('.connection-status');
        if (connStatusEl) {
            connStatusEl.innerHTML = '<span class="status-dot connected"></span><svg viewBox="0 0 24 24" width="15" height="15" stroke="currentColor" stroke-width="2.2" fill="none"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg><span>Connected & E2EE Secured</span>';
        }
        if (handshakeResolve) {
            handshakeResolve();
        }
        if (filesToTransfer.length > 0) {
            sendBtn.disabled = false;
        }
    }
}

// --- PeerJS Logic ---

function initPeer(roomId) {
    const fullPeerId = APP_PREFIX + roomId;
    const tempPeer = new Peer(peerConfig);
    
    tempPeer.on('open', (id) => {
        console.log('[NET] Peer open');
        const conn = tempPeer.connect(fullPeerId);
        setupPeerConnectionLogging(conn);
        
        const connectTimeout = setTimeout(() => {
            if (!dataConnection) {
                conn.close();
                tempPeer.destroy();
                roomStatus.innerText = 'Connection timed out. Check the code or try again.';
                joinBtn.disabled = false;
                createBtn.disabled = false;
            }
        }, 30000); // 30 seconds for WebRTC ICE negotiation

        const runHandshake = async () => {
            if (!myKeyPair) {
                clearTimeout(connectTimeout);
                roomStatus.innerText = 'Connected to peer! Negotiating E2EE...';
                setupConnection(conn);
                peer = tempPeer;
                showTransferSection();
                await startE2EEHandshake();
            }
        };

        conn.on('open', async () => {
            await runHandshake();
        });
        
        // Backup trigger for mobile browsers where open event may fire instantaneously
        setTimeout(async () => {
            if (conn.open && !myKeyPair) {
                await runHandshake();
            }
        }, 300);

        conn.on('error', (err) => {
            clearTimeout(connectTimeout);
            tempPeer.destroy();
            roomStatus.innerText = 'Failed to connect. Code might be invalid or peer offline.';
            joinBtn.disabled = false;
            createBtn.disabled = false;
        });
    });

    tempPeer.on('error', (err) => {
        console.error('Peer error:', err);
        roomStatus.innerText = 'Connection error: ' + (err.message || err.type);
        joinBtn.disabled = false;
        createBtn.disabled = false;
    });
}

function createRoom(roomId) {
    const fullPeerId = APP_PREFIX + roomId;
    roomStatus.innerText = 'Room created. Waiting for peer to join...';
    peer = new Peer(fullPeerId, peerConfig);
    
    peer.on('open', (id) => {
        console.log('[NET] Peer open');
        console.log('Room created with ID:', id);
    });
    
    peer.on('connection', async (conn) => {
        if (dataConnection) {
            conn.close();
            return;
        }
        setupPeerConnectionLogging(conn);
        roomStatus.innerText = 'Peer joined! Negotiating E2EE...';
        setupConnection(conn);
        showTransferSection();

        const runHandshake = async () => {
            if (!myKeyPair) {
                await startE2EEHandshake();
            }
        };

        if (conn.open) {
            await runHandshake();
        } else {
            conn.on('open', async () => {
                await runHandshake();
            });
            // Backup check for mobile browsers where open event fires right before listener registration
            setTimeout(async () => {
                if (conn.open && !myKeyPair) {
                    await runHandshake();
                }
            }, 300);
        }
    });
    
    peer.on('error', (err) => {
        if (err.type === 'unavailable-id') {
            roomStatus.innerText = 'Room already exists and is full or busy.';
            joinBtn.disabled = false;
            createBtn.disabled = false;
        } else {
            roomStatus.innerText = 'Connection error: ' + err.message;
            joinBtn.disabled = false;
            createBtn.disabled = false;
        }
    });
}

// =========================================================================
// REAL-TIME PERFORMANCE MONITOR & TRANSFER ENGINE
// =========================================================================

const transferEngine = {
    active: false,
    direction: 'idle', // 'sending' | 'receiving'
    fileName: '',
    fileSize: 0,
    fileType: '',
    bytesTransferred: 0,
    startTime: 0,
    samples: [],
    speedHistory: new Array(30).fill(0),
    timerId: null,
    perfLogTimerId: null,
    connectionType: 'Direct P2P',
    isCancelled: false,

    start(dir, name, size, type) {
        this.active = true;
        this.direction = dir;
        this.fileName = name;
        this.fileSize = size;
        this.fileType = type || 'application/octet-stream';
        this.bytesTransferred = 0;
        this.startTime = performance.now();
        this.samples = [{ time: this.startTime, bytes: 0 }];
        this.speedHistory = new Array(30).fill(0);
        this.isCancelled = false;

        this.detectConnectionType();
        this.renderInitialUI();

        if (this.timerId) clearInterval(this.timerId);
        // Throttled UI update loop: 10 Hz (100ms interval)
        this.timerId = setInterval(() => this.tick(), 100);

        if (this.perfLogTimerId) clearInterval(this.perfLogTimerId);
        // Periodic console debug logger: 1 Hz (1000ms interval)
        this.perfLogTimerId = setInterval(() => this.logPerf(), 1000);
    },

    updateBytes(bytes) {
        this.bytesTransferred = bytes;
    },

    detectConnectionType() {
        const pc = dataConnection ? (dataConnection.peerConnection || dataConnection._peerConnection) : null;
        if (!pc) return;

        if (pc.getStats) {
            pc.getStats().then(stats => {
                let isRelay = false;
                stats.forEach(report => {
                    if (report.type === 'candidate-pair' && (report.state === 'succeeded' || report.selected)) {
                        const localCand = stats.get(report.localCandidateId);
                        const remoteCand = stats.get(report.remoteCandidateId);
                        if ((localCand && localCand.candidateType === 'relay') || (remoteCand && remoteCand.candidateType === 'relay')) {
                            isRelay = true;
                        }
                    }
                });
                this.connectionType = isRelay ? 'TURN Relay' : 'Direct P2P';
                this.updateConnPill();
            }).catch(() => {});
        }
    },

    updateConnPill() {
        const connTypeEl = document.getElementById('perf-conn-type');
        const connPill = document.getElementById('perf-conn-pill');
        if (connTypeEl) connTypeEl.innerText = this.connectionType;
        if (connPill) {
            if (this.connectionType.includes('Relay')) {
                connPill.className = 'perf-conn-pill relay';
            } else {
                connPill.className = 'perf-conn-pill direct';
            }
        }
    },

    tick() {
        if (!this.active) return;

        const now = performance.now();
        const elapsedSec = (now - this.startTime) / 1000;

        // Add sample to rolling window
        this.samples.push({ time: now, bytes: this.bytesTransferred });

        // Keep samples from last 1000ms (rolling window)
        while (this.samples.length > 1 && (now - this.samples[0].time) > 1000) {
            this.samples.shift();
        }

        // Rolling speed calculation
        let currentSpeedBytesPerSec = 0;
        if (this.samples.length > 1) {
            const oldest = this.samples[0];
            const timeDiff = (now - oldest.time) / 1000;
            const bytesDiff = this.bytesTransferred - oldest.bytes;
            if (timeDiff > 0) currentSpeedBytesPerSec = bytesDiff / timeDiff;
        }

        const currentMBs = currentSpeedBytesPerSec / (1024 * 1024);
        const currentMbps = (currentSpeedBytesPerSec * 8) / 1000000;

        // Average speed calculation
        const avgSpeedBytesPerSec = elapsedSec > 0 ? (this.bytesTransferred / elapsedSec) : 0;
        const avgMBs = avgSpeedBytesPerSec / (1024 * 1024);

        // Accurate percentage derived strictly from bytes
        const percent = this.fileSize > 0 ? Math.min(100, (this.bytesTransferred / this.fileSize) * 100) : 0;

        // ETA calculation
        const remainingBytes = Math.max(0, this.fileSize - this.bytesTransferred);
        let etaText = 'Calculating...';
        if (percent >= 100) {
            etaText = 'Complete';
        } else if (currentSpeedBytesPerSec > 0) {
            const etaSec = Math.ceil(remainingBytes / currentSpeedBytesPerSec);
            etaText = this.formatSeconds(etaSec);
        }

        // Update graph history
        this.speedHistory.push(currentMBs);
        if (this.speedHistory.length > 30) this.speedHistory.shift();

        this.renderUI(percent, currentMBs, currentMbps, avgMBs, etaText);
        this.drawSpeedGraph();
    },

    formatSeconds(totalSec) {
        const m = Math.floor(totalSec / 60);
        const s = totalSec % 60;
        return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')} remaining`;
    },

    renderInitialUI() {
        if (progressContainer) progressContainer.classList.remove('hidden');

        const dirIcon = document.getElementById('perf-dir-icon');
        const dirText = document.getElementById('perf-dir-text');
        const fileNameEl = document.getElementById('perf-file-name');
        const fileSubEl = document.getElementById('perf-file-sub');

        if (dirIcon) dirIcon.innerText = this.direction === 'sending' ? '↑' : '↓';
        if (dirText) dirText.innerText = this.direction === 'sending' ? 'Sending' : 'Receiving';
        if (fileNameEl) {
            fileNameEl.innerText = this.fileName;
            fileNameEl.title = this.fileName;
        }
        if (fileSubEl) {
            fileSubEl.innerText = `${formatBytes(this.fileSize)} • ${this.fileType || 'binary'}`;
        }

        this.updateConnPill();
    },

    renderUI(percent, currentMBs, currentMbps, avgMBs, etaText) {
        if (progressBar) progressBar.style.width = `${percent.toFixed(1)}%`;
        if (progressPercentage) progressPercentage.innerText = `${percent.toFixed(1)}%`;

        const sizeVal = document.getElementById('perf-size');
        const speedPrimary = document.getElementById('perf-speed-primary');
        const speedSecondary = document.getElementById('perf-speed-secondary');
        const avgSpeed = document.getElementById('perf-avg-speed');
        const etaVal = document.getElementById('perf-eta');

        if (sizeVal) sizeVal.innerText = `${formatBytes(this.bytesTransferred)} / ${formatBytes(this.fileSize)}`;
        if (speedPrimary) speedPrimary.innerText = `${currentMBs.toFixed(2)} MB/s`;
        if (speedSecondary) speedSecondary.innerText = `${currentMbps.toFixed(2)} Mbps`;
        if (avgSpeed) avgSpeed.innerText = `${avgMBs.toFixed(2)} MB/s`;
        if (etaVal) etaVal.innerText = etaText;
    },

    drawSpeedGraph() {
        const canvas = document.getElementById('speed-graph-canvas');
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        const width = canvas.width;
        const height = canvas.height;

        ctx.clearRect(0, 0, width, height);

        const maxSpeed = Math.max(1, ...this.speedHistory);
        const padding = 4;
        const graphHeight = height - padding * 2;
        const stepX = width / (this.speedHistory.length - 1);

        // Background grid line
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(0, height / 2);
        ctx.lineTo(width, height / 2);
        ctx.stroke();

        // Area fill
        const gradient = ctx.createLinearGradient(0, 0, 0, height);
        gradient.addColorStop(0, 'rgba(0, 198, 255, 0.3)');
        gradient.addColorStop(1, 'rgba(0, 198, 255, 0.0)');

        ctx.beginPath();
        ctx.moveTo(0, height);
        for (let i = 0; i < this.speedHistory.length; i++) {
            const x = i * stepX;
            const y = height - padding - (this.speedHistory[i] / maxSpeed) * graphHeight;
            ctx.lineTo(x, y);
        }
        ctx.lineTo(width, height);
        ctx.closePath();
        ctx.fillStyle = gradient;
        ctx.fill();

        // Glowing speed line
        ctx.beginPath();
        for (let i = 0; i < this.speedHistory.length; i++) {
            const x = i * stepX;
            const y = height - padding - (this.speedHistory[i] / maxSpeed) * graphHeight;
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        }
        ctx.strokeStyle = '#00c6ff';
        ctx.lineWidth = 2;
        ctx.stroke();
    },

    finish(success = true) {
        if (!this.active) return;
        this.active = false;

        if (this.timerId) clearInterval(this.timerId);
        if (this.perfLogTimerId) clearInterval(this.perfLogTimerId);

        const durationSec = ((performance.now() - this.startTime) / 1000).toFixed(2);
        const avgMBs = durationSec > 0 ? ((this.fileSize / (1024 * 1024)) / durationSec).toFixed(2) : '0.00';

        if (success) {
            if (progressBar) progressBar.style.width = '100%';
            if (progressPercentage) progressPercentage.innerText = '100.0%';

            const etaVal = document.getElementById('perf-eta');
            if (etaVal) etaVal.innerText = '✓ Complete';

            const sizeVal = document.getElementById('perf-size');
            if (sizeVal) sizeVal.innerText = `${formatBytes(this.fileSize)} / ${formatBytes(this.fileSize)}`;

            const avgSpeed = document.getElementById('perf-avg-speed');
            if (avgSpeed) avgSpeed.innerText = `${avgMBs} MB/s (${durationSec}s)`;

            console.log(`[PERF COMPLETE] Transferred ${formatBytes(this.fileSize)} in ${durationSec}s at avg ${avgMBs} MB/s`);
        }
    },

    cancel() {
        this.isCancelled = true;
        this.active = false;

        if (this.timerId) clearInterval(this.timerId);
        if (this.perfLogTimerId) clearInterval(this.perfLogTimerId);

        const etaVal = document.getElementById('perf-eta');
        if (etaVal) etaVal.innerText = 'Cancelled';

        const sizeVal = document.getElementById('perf-size');
        if (sizeVal) sizeVal.innerText = 'Transfer Cancelled';

        if (dataConnection && dataConnection.open) {
            try {
                dataConnection.send(JSON.stringify({ type: 'transfer-cancelled' }));
            } catch (e) {}
        }
    },

    reset() {
        this.active = false;
        this.isCancelled = false;
        if (this.timerId) clearInterval(this.timerId);
        if (this.perfLogTimerId) clearInterval(this.perfLogTimerId);
        if (progressContainer) progressContainer.classList.add('hidden');
    },

    logPerf() {
        if (!this.active) return;
        const elapsedSec = (performance.now() - this.startTime) / 1000;
        const avgMBs = elapsedSec > 0 ? (this.bytesTransferred / (1024 * 1024 * elapsedSec)).toFixed(2) : '0.00';
        const percent = this.fileSize > 0 ? ((this.bytesTransferred / this.fileSize) * 100).toFixed(2) : '0';
        const currentMBs = (this.speedHistory[this.speedHistory.length - 1] || 0).toFixed(2);
        console.log(`[PERF] Transferred: ${formatBytes(this.bytesTransferred)} / ${formatBytes(this.fileSize)} | Progress: ${percent}% | Current: ${currentMBs} MB/s | Average: ${avgMBs} MB/s | Connection: ${this.connectionType}`);
    }
};

function setupConnection(conn) {
    dataConnection = conn;
    
    dataConnection.on('data', async (data) => {
        if (typeof data === 'string') {
            const meta = JSON.parse(data);
            
            if (meta.type === 'ecdh-public-key') {
                console.log('[HANDSHAKE] Remote public key received');
                try {
                    const remotePub = await importPublicKey(meta.key);
                    sharedCryptoKey = await deriveAESKey(myKeyPair.privateKey, remotePub);
                    console.log('[HANDSHAKE] Shared AES key derived');
                    localE2EEReady = true;
                    dataConnection.send(JSON.stringify({ type: 'e2ee-ready' }));
                    console.log('[HANDSHAKE] Local E2EE ready sent');
                    checkE2EEComplete();
                } catch (e) {
                    console.error("E2EE Handshake failed", e);
                }
            } else if (meta.type === 'e2ee-ready') {
                remoteE2EEReady = true;
                console.log('[HANDSHAKE] Remote E2EE ready received');
                checkE2EEComplete();
            } else if (meta.type === 'file-start') {
                decryptionQueue = decryptionQueue.then(async () => {
                    await handshakePromise;
                    incomingFileInfo = meta;
                    incomingFileData = [];
                    receivedSize = 0;
                    receivedChunks = 0;
                    expectedChunks = meta.totalChunks || 0;
                    console.log(`[RECEIVER] file-start: name=${meta.name}, size=${meta.size}, fileIndex=${meta.fileIndex + 1}/${meta.totalFiles}`);
                    
                    transferEngine.start('receiving', meta.name, meta.size, meta.fileType);
                });
            } else if (meta.type === 'file-end') {
                decryptionQueue.then(async () => {
                    await handshakePromise;
                    console.log(`[RECEIVER] file-end received for ${incomingFileInfo.name}. Verified bytes: ${receivedSize}/${incomingFileInfo.size}`);
                    
                    if (receivedSize === incomingFileInfo.size) {
                        transferEngine.finish(true);
                        saveReceivedFile();
                    } else {
                        console.error(`[RECEIVER] Mismatch! Expected ${incomingFileInfo.size} bytes, got ${receivedSize} bytes.`);
                        transferEngine.finish(false);
                    }
                });
            } else if (meta.type === 'transfer-cancelled') {
                console.log('[RECEIVER] Sender cancelled the transfer');
                transferEngine.cancel();
                incomingFileData = [];
            }
        } else {
            // Binary data (Encrypted ArrayBuffer)
            decryptionQueue = decryptionQueue.then(async () => {
                await handshakePromise;
                if (transferEngine.isCancelled) return;
                try {
                    let payload;
                    if (data instanceof Blob) {
                        payload = new Uint8Array(await data.arrayBuffer());
                    } else {
                        payload = new Uint8Array(data);
                    }

                    if (payload.length <= 12) return;
                    
                    const iv = payload.slice(0, 12);
                    const encryptedChunk = payload.slice(12);

                    const decryptedChunk = await window.crypto.subtle.decrypt(
                        { name: 'AES-GCM', iv: iv },
                        sharedCryptoKey,
                        encryptedChunk
                    );
                    incomingFileData.push(decryptedChunk);
                    receivedChunks++;
                    receivedSize += decryptedChunk.byteLength;
                    
                    // Decoupled throttled engine update (no heavy DOM updates per chunk!)
                    transferEngine.updateBytes(receivedSize);
                } catch (err) {
                    console.error(`[RECEIVER] Decryption FAILED for chunk #${receivedChunks}:`, err);
                }
            });
        }
    });
    
    dataConnection.on('close', () => {
        resetTransferState();
        roomSection.classList.remove('hidden');
        roomSection.classList.add('active');
        transferSection.classList.remove('active');
        setTimeout(() => {
            transferSection.classList.add('hidden');
        }, 400);
        roomStatus.innerText = 'Peer disconnected. Room closed.';
        if (peer) {
            peer.destroy();
            peer = null;
        }
        dataConnection = null;
        sharedCryptoKey = null;
        localE2EEReady = false;
        remoteE2EEReady = false;
        document.querySelector('.connection-status').innerHTML = '<span class="status-dot connected"></span> Connected to peer';
    });
}

// UI Handlers
roomInput.addEventListener('input', (e) => {
    e.target.value = e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
});

joinBtn.addEventListener('click', () => {
    const roomId = roomInput.value.trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (roomId.length === 4) {
        joinBtn.disabled = true;
        createBtn.disabled = true;
        roomStatus.innerText = 'Connecting...';
        initPeer(roomId);
    } else {
        roomStatus.innerText = 'Please enter a valid 4-character code.';
    }
});

createBtn.addEventListener('click', () => {
    createBtn.disabled = true;
    joinBtn.disabled = true;
    const newCode = generateRoomCode();
    generatedCodeSpan.innerText = newCode;
    createdCodeContainer.classList.remove('hidden');
    renderQRCode(newCode);
    createRoom(newCode);
});

copyBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(generatedCodeSpan.innerText);
    copyBtn.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16" stroke="#10b981" stroke-width="2.5" fill="none"><polyline points="20 6 9 17 4 12"></polyline></svg>';
    setTimeout(() => { 
        copyBtn.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>'; 
    }, 2000);
});

document.querySelectorAll('.reload-action-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        window.location.reload();
    });
});

if (sendAnotherBtn) {
    sendAnotherBtn.addEventListener('click', () => {
        resetFileSelection();
        progressContainer.classList.add('hidden');
        fileInput.click();
    });
}

function generateRoomCode() {
    const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    let code = '';
    for(let i=0; i<2; i++) code += letters.charAt(Math.floor(Math.random() * letters.length));
    for(let i=0; i<2; i++) code += numbers.charAt(Math.floor(Math.random() * numbers.length));
    return code;
}

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        filesToTransfer = Array.from(e.target.files);
        if (filesToTransfer.length === 1) {
            selectedFileName.innerHTML = `<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg> ${filesToTransfer[0].name} (${formatBytes(filesToTransfer[0].size)})`;
        } else {
            const totalSize = filesToTransfer.reduce((sum, f) => sum + f.size, 0);
            selectedFileName.innerHTML = `<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg> ${filesToTransfer.length} files selected (${formatBytes(totalSize)} total):\n` +
                filesToTransfer.map(f => f.name).join(', ');
        }
        selectedFileName.style.display = 'inline-block';
        const promptEl = uploadArea.querySelector('.upload-prompt');
        const iconEl = uploadArea.querySelector('.upload-icon-circle');
        if (promptEl) promptEl.style.display = 'none';
        if (iconEl) iconEl.style.display = 'none';
        
        if (dataConnection && dataConnection.open && sharedCryptoKey && localE2EEReady && remoteE2EEReady) {
            sendBtn.disabled = false;
        }
    }
});

sendBtn.addEventListener('click', () => {
    if (filesToTransfer.length > 0 && dataConnection && dataConnection.open && sharedCryptoKey && localE2EEReady && remoteE2EEReady) {
        sendBatchFiles();
    }
});

const cancelTransferBtn = document.getElementById('cancel-transfer-btn');
if (cancelTransferBtn) {
    cancelTransferBtn.addEventListener('click', () => {
        transferEngine.cancel();
    });
}

function sendSingleFile(file, fileIndex, totalFiles) {
    return new Promise((resolve, reject) => {
        const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
        console.log(`[SENDER] Starting transfer [${fileIndex + 1}/${totalFiles}]: name=${file.name}, size=${file.size}, totalChunks=${totalChunks}`);
        
        transferEngine.start('sending', file.name, file.size, file.type);

        dataConnection.send(JSON.stringify({
            type: 'file-start',
            name: file.name,
            size: file.size,
            fileType: file.type,
            totalChunks: totalChunks,
            fileIndex: fileIndex,
            totalFiles: totalFiles
        }));

        let chunkIndex = 0;
        let offset = 0;

        function readNextChunk() {
            if (transferEngine.isCancelled) {
                console.log('[SENDER] Transfer cancelled by user.');
                resolve();
                return;
            }

            if (offset >= file.size) {
                console.log(`[SENDER] All chunks queued for ${file.name}. Sending file-end.`);
                dataConnection.send(JSON.stringify({ type: 'file-end' }));
                transferEngine.finish(true);
                resolve();
                return;
            }

            const slice = file.slice(offset, offset + CHUNK_SIZE);
            const reader = new FileReader();

            reader.onload = async (e) => {
                if (transferEngine.isCancelled) {
                    resolve();
                    return;
                }

                const rawBytes = new Uint8Array(e.target.result);
                
                const iv = window.crypto.getRandomValues(new Uint8Array(12));
                const encryptedChunk = await window.crypto.subtle.encrypt(
                    { name: 'AES-GCM', iv: iv },
                    sharedCryptoKey,
                    rawBytes
                );

                const payload = new Uint8Array(iv.length + encryptedChunk.byteLength);
                payload.set(iv, 0);
                payload.set(new Uint8Array(encryptedChunk), iv.length);

                dataConnection.send(payload.buffer);
                chunkIndex++;
                offset += slice.size;

                // Throttled performance byte update
                transferEngine.updateBytes(offset);

                if (dataConnection.bufferedAmount > 64 * 1024) {
                    setTimeout(readNextChunk, 10);
                } else {
                    setTimeout(readNextChunk, 0);
                }
            };

            reader.onerror = (err) => {
                console.error("[SENDER] FileReader error:", err);
                transferEngine.finish(false);
                reject(err);
            };

            reader.readAsArrayBuffer(slice);
        }

        readNextChunk();
    });
}

async function sendBatchFiles() {
    sendBtn.disabled = true;
    fileInput.disabled = true;
    progressContainer.classList.remove('hidden');
    
    const totalFiles = filesToTransfer.length;
    for (let i = 0; i < totalFiles; i++) {
        await sendSingleFile(filesToTransfer[i], i, totalFiles);
    }
    
    if (sendAnotherBtn) {
        sendAnotherBtn.classList.remove('hidden');
    }
    fileInput.disabled = false;
}

function saveReceivedFile() {
    console.log(`[RECEIVER] Reconstructing blob from ${incomingFileData.length} decrypted chunks...`);
    const blob = new Blob(incomingFileData, { type: incomingFileInfo.fileType || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    console.log(`[RECEIVER] Blob created successfully! size=${blob.size}, type=${blob.type}`);

    downloadContainer.classList.remove('hidden');

    if (downloadList) {
        const item = document.createElement('a');
        item.className = 'download-item-btn';
        item.href = url;
        item.download = incomingFileInfo.name;
        item.innerHTML = `<span class="file-item-label"><svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg> ${incomingFileInfo.name} (${formatBytes(incomingFileInfo.size)})</span><span class="dl-btn-text"><svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg> Download</span>`;
        downloadList.appendChild(item);
    }

    const currentFileNum = (incomingFileInfo.fileIndex || 0) + 1;
    const totalFiles = incomingFileInfo.totalFiles || 1;

    if (downloadStatusText) {
        if (currentFileNum === totalFiles) {
            downloadStatusText.innerText = `All ${totalFiles} file(s) received successfully!`;
            progressText.innerText = 'Received successfully!';
        } else {
            downloadStatusText.innerText = `Received ${currentFileNum} of ${totalFiles} file(s)...`;
        }
    }
    
    fileInput.disabled = false;
}

function updateProgress(percentage) {
    progressBar.style.width = `${percentage}%`;
    progressPercentage.innerText = `${percentage}%`;
}

function showTransferSection() {
    roomSection.classList.remove('active');
    const glassContainer = document.querySelector('.glass-container');
    if (glassContainer) glassContainer.classList.add('wide');
    setTimeout(() => {
        roomSection.classList.add('hidden');
        transferSection.classList.remove('hidden');
        transferSection.classList.add('active');
    }, 400);
}

function resetFileSelection() {
    filesToTransfer = [];
    fileInput.value = '';
    selectedFileName.style.display = 'none';
    selectedFileName.innerText = '';
    const promptEl = uploadArea.querySelector('.upload-prompt');
    const iconEl = uploadArea.querySelector('.upload-icon-circle');
    if (promptEl) promptEl.style.display = 'block';
    if (iconEl) iconEl.style.display = 'flex';
    sendBtn.disabled = true;
}

function resetTransferState() {
    joinBtn.disabled = false;
    createBtn.disabled = false;
    resetFileSelection();
    transferEngine.reset();
    downloadContainer.classList.add('hidden');
    if (downloadList) downloadList.innerHTML = '';
    localE2EEReady = false;
    remoteE2EEReady = false;
    sharedCryptoKey = null;
    const glassContainer = document.querySelector('.glass-container');
    if (glassContainer) glassContainer.classList.remove('wide');
    document.querySelector('.connection-status').innerHTML = '<span class="status-dot connected"></span> Connected to peer';
}

function renderQRCode(code) {
    const qrBox = document.getElementById('qr-code-box');
    const canvas = document.getElementById('qr-canvas');
    if (!qrBox || !canvas) return;

    qrBox.classList.remove('hidden');

    const joinUrl = `${window.location.origin}${window.location.pathname}?room=${code}`;

    if (window.QRCode && window.QRCode.toCanvas) {
        window.QRCode.toCanvas(canvas, joinUrl, {
            width: 160,
            margin: 1,
            color: {
                dark: '#0f172a',
                light: '#ffffff'
            }
        }, function (error) {
            if (error) console.error("[QR GENERATOR] Error:", error);
        });
    } else {
        // Fallback simple renderer
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#0f172a';
        const size = 160;
        const cells = 21;
        const cellSize = size / cells;
        let hash = 0;
        for (let i = 0; i < code.length; i++) hash = (hash << 5) - hash + code.charCodeAt(i);
        function drawFinder(x, y) {
            ctx.fillRect(x * cellSize, y * cellSize, 7 * cellSize, 7 * cellSize);
            ctx.fillStyle = '#ffffff';
            ctx.fillRect((x + 1) * cellSize, (y + 1) * cellSize, 5 * cellSize, 5 * cellSize);
            ctx.fillStyle = '#0f172a';
            ctx.fillRect((x + 2) * cellSize, (y + 2) * cellSize, 3 * cellSize, 3 * cellSize);
        }
        drawFinder(0, 0);
        drawFinder(14, 0);
        drawFinder(0, 14);
        for (let r = 0; r < cells; r++) {
            for (let c = 0; c < cells; c++) {
                if ((r < 8 && c < 8) || (r < 8 && c > 12) || (r > 12 && c < 8)) continue;
                const bit = Math.abs(Math.sin(r * 12.9898 + c * 78.233 + hash) * 43758.5453) % 1;
                if (bit > 0.45) {
                    ctx.fillRect(c * cellSize, r * cellSize, cellSize, cellSize);
                }
            }
        }
    }
}

// =========================================================================
// CAMERA QR CODE SCANNER & AUTO-JOIN
// =========================================================================

let scannerStream = null;
let scannerAnimId = null;

const scanQrBtn = document.getElementById('scan-qr-btn');
const scannerModal = document.getElementById('scanner-modal');
const closeScannerBtn = document.getElementById('close-scanner-btn');
const scannerVideo = document.getElementById('scanner-video');
const scannerCanvas = document.getElementById('scanner-canvas');
const scannerStatus = document.getElementById('scanner-status');

if (scanQrBtn) {
    scanQrBtn.addEventListener('click', startQRScanner);
}

if (closeScannerBtn) {
    closeScannerBtn.addEventListener('click', stopQRScanner);
}

async function startQRScanner() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        alert('Camera access is not supported on your browser or requires HTTPS.');
        return;
    }

    try {
        scannerStream = await navigator.mediaDevices.getUserMedia({
            video: { facingMode: 'environment' }
        });
        scannerVideo.srcObject = scannerStream;
        await scannerVideo.play();

        scannerModal.classList.remove('hidden');
        if (scannerStatus) scannerStatus.innerText = 'Position camera over QR code';
        scanFrameLoop();
    } catch (err) {
        console.error('[QR SCANNER] Camera permission error:', err);
        alert('Could not access camera: ' + (err.message || 'Permission denied'));
    }
}

function stopQRScanner() {
    if (scannerAnimId) {
        cancelAnimationFrame(scannerAnimId);
        scannerAnimId = null;
    }
    if (scannerStream) {
        scannerStream.getTracks().forEach(track => track.stop());
        scannerStream = null;
    }
    if (scannerVideo) {
        scannerVideo.srcObject = null;
    }
    if (scannerModal) {
        scannerModal.classList.add('hidden');
    }
}

function scanFrameLoop() {
    if (!scannerVideo || scannerVideo.readyState !== scannerVideo.HAVE_ENOUGH_DATA) {
        scannerAnimId = requestAnimationFrame(scanFrameLoop);
        return;
    }

    const width = scannerVideo.videoWidth;
    const height = scannerVideo.videoHeight;
    scannerCanvas.width = width;
    scannerCanvas.height = height;

    const ctx = scannerCanvas.getContext('2d');
    ctx.drawImage(scannerVideo, 0, 0, width, height);

    const imageData = ctx.getImageData(0, 0, width, height);

    if (window.jsQR) {
        const code = window.jsQR(imageData.data, imageData.width, imageData.height, {
            inversionAttempts: 'dontInvert'
        });

        if (code && code.data) {
            console.log('[QR SCANNER] Scanned payload:', code.data);
            let roomCode = code.data.trim();

            try {
                const parsedUrl = new URL(roomCode);
                const paramRoom = parsedUrl.searchParams.get('room');
                if (paramRoom) roomCode = paramRoom;
            } catch (e) {
                // Not a URL, use raw string
            }

            roomCode = roomCode.toUpperCase().replace(/[^A-Z0-9]/g, '');

            if (roomCode.length === 4) {
                if (scannerStatus) scannerStatus.innerText = `Code Found: ${roomCode}! Connecting...`;
                stopQRScanner();
                roomInput.value = roomCode;
                joinBtn.click();
                return;
            }
        }
    }

    scannerAnimId = requestAnimationFrame(scanFrameLoop);
}

// Auto-join if user scanned QR code with native phone camera app
window.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const autoRoom = urlParams.get('room');
    if (autoRoom) {
        const cleanCode = autoRoom.trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
        if (cleanCode.length === 4) {
            roomInput.value = cleanCode;
            console.log(`[AUTO-JOIN] Room parameter detected in URL: ${cleanCode}. Joining...`);
            setTimeout(() => {
                joinBtn.click();
            }, 400);
        }
    }
});
