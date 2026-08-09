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
                    
                    progressContainer.classList.remove('hidden');
                    progressText.innerText = `Receiving (${(meta.fileIndex || 0) + 1}/${meta.totalFiles || 1}): ${meta.name}`;
                    updateProgress(0);
                });
            } else if (meta.type === 'file-end') {
                decryptionQueue.then(async () => {
                    await handshakePromise;
                    console.log(`[RECEIVER] file-end received for ${incomingFileInfo.name}.`);
                    saveReceivedFile();
                });
            }
        } else {
            // Binary data (Encrypted ArrayBuffer)
            decryptionQueue = decryptionQueue.then(async () => {
                await handshakePromise;
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
                    
                    const percentage = Math.round((receivedSize / incomingFileInfo.size) * 100);
                    updateProgress(percentage);
                } catch (err) {
                    console.error(`[RECEIVER] Decryption FAILED for chunk #${receivedChunks}:`, err);
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
                    
                    progressContainer.classList.remove('hidden');
                    progressText.innerText = `Receiving (${(meta.fileIndex || 0) + 1}/${meta.totalFiles || 1}): ${meta.name}`;
                    updateProgress(0);
                });
            } else if (meta.type === 'file-end') {
                decryptionQueue.then(async () => {
                    await handshakePromise;
                    console.log(`[RECEIVER] file-end received for ${incomingFileInfo.name}.`);
                    saveReceivedFile();
                });
            }
        } else {
            // Binary data (Encrypted ArrayBuffer)
            decryptionQueue = decryptionQueue.then(async () => {
                await handshakePromise;
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
                    
                    const percentage = Math.round((receivedSize / incomingFileInfo.size) * 100);
                    updateProgress(percentage);
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

function sendSingleFile(file, fileIndex, totalFiles) {
    return new Promise((resolve, reject) => {
        const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
        console.log(`[SENDER] Starting transfer [${fileIndex + 1}/${totalFiles}]: name=${file.name}, size=${file.size}, totalChunks=${totalChunks}`);
        
        progressText.innerText = `Sending (${fileIndex + 1}/${totalFiles}): ${file.name}`;
        updateProgress(0);

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
            if (offset >= file.size) {
                console.log(`[SENDER] All chunks queued for ${file.name}. Sending file-end.`);
                dataConnection.send(JSON.stringify({ type: 'file-end' }));
                progressText.innerText = `Sent (${fileIndex + 1}/${totalFiles}): ${file.name}`;
                updateProgress(100);
                resolve();
                return;
            }

            const slice = file.slice(offset, offset + CHUNK_SIZE);
            const reader = new FileReader();

            reader.onload = async (e) => {
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

                const percent = Math.floor((offset / file.size) * 100);
                updateProgress(percent);

                if (dataConnection.bufferedAmount > 64 * 1024) {
                    setTimeout(readNextChunk, 10);
                } else {
                    setTimeout(readNextChunk, 0);
                }
            };

            reader.onerror = (err) => {
                console.error("[SENDER] FileReader error:", err);
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
    progressContainer.classList.add('hidden');
    downloadContainer.classList.add('hidden');
    if (downloadList) downloadList.innerHTML = '';
    updateProgress(0);
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
