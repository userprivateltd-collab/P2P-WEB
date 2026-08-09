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

const createBtn = document.getElementById('create-btn');
const createdCodeContainer = document.getElementById('created-code-container');
const generatedCodeSpan = document.getElementById('generated-code');
const copyBtn = document.getElementById('copy-btn');

const progressContainer = document.getElementById('progress-container');
const progressText = document.getElementById('progress-text');
const progressBar = document.getElementById('progress-bar');
const progressPercentage = document.getElementById('progress-percentage');
const downloadContainer = document.getElementById('download-container');
const downloadLink = document.getElementById('download-link');

let peer = null;
let dataConnection = null;
let fileToSend = null;

// E2EE State
let myKeyPair = null;
let sharedCryptoKey = null;
let handshakeResolve = null;
let handshakePromise = null;

function resetHandshakeGate() {
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

async function performHandshake() {
    // myKeyPair is pre-generated before this is called
    const pubJwk = await exportPublicKey(myKeyPair.publicKey);
    dataConnection.send(JSON.stringify({
        type: 'ecdh-public-key',
        key: pubJwk
    }));
}

// --- PeerJS Logic ---

function initPeer(roomId) {
    const fullPeerId = APP_PREFIX + roomId;
    const tempPeer = new Peer();
    
    tempPeer.on('open', (id) => {
        const conn = tempPeer.connect(fullPeerId, { serialization: 'raw', reliable: true });
        
        conn.on('open', async () => {
            roomStatus.innerText = 'Connected to peer! Negotiating E2EE...';
            resetHandshakeGate();
            myKeyPair = await generateECDHKeyPair(); // Generate BEFORE registering data handler
            setupConnection(conn);
            peer = tempPeer;
            showTransferSection();
            performHandshake(); // Send public key
            
            peer.on('error', (err) => console.error(err));
        });
        
        conn.on('error', (err) => {
            tempPeer.destroy();
            roomStatus.innerText = 'Failed to connect. Code might be invalid or peer offline.';
            joinBtn.disabled = false;
        });
        
        setTimeout(() => {
            if (!dataConnection) {
                conn.close();
                tempPeer.destroy();
                roomStatus.innerText = 'Connection timed out. Check the code and try again.';
                joinBtn.disabled = false;
            }
        }, 5000);
    });
}

function createRoom(roomId) {
    const fullPeerId = APP_PREFIX + roomId;
    roomStatus.innerText = 'Room created. Waiting for peer to join...';
    peer = new Peer(fullPeerId);
    
    peer.on('open', (id) => {
        console.log('Room created with ID:', id);
    });
    
    peer.on('connection', async (conn) => {
        if (dataConnection) {
            conn.close();
            return;
        }
        roomStatus.innerText = 'Peer joined! Negotiating E2EE...';
        resetHandshakeGate();
        myKeyPair = await generateECDHKeyPair(); // Generate BEFORE registering data handler
        setupConnection(conn);
        showTransferSection();
        performHandshake(); // Send public key
    });
    
    peer.on('error', (err) => {
        if (err.type === 'unavailable-id') {
            roomStatus.innerText = 'Room already exists and is full or busy.';
            joinBtn.disabled = false;
        } else {
            roomStatus.innerText = 'Connection error: ' + err.message;
            joinBtn.disabled = false;
        }
    });
}

function setupConnection(conn) {
    dataConnection = conn;
    
    dataConnection.on('data', async (data) => {
        if (typeof data === 'string') {
            const meta = JSON.parse(data);
            
            if (meta.type === 'ecdh-public-key') {
                try {
                    const remotePub = await importPublicKey(meta.key);
                    sharedCryptoKey = await deriveAESKey(myKeyPair.privateKey, remotePub);
                    handshakeResolve(); // Unblock any waiting binary chunks
                    console.log('[RECEIVER] E2EE handshake complete. sharedCryptoKey derived.');
                    roomStatus.innerText = 'Connected & E2EE Secured 🔒';
                    // Update UI in transfer section too
                    document.querySelector('.connection-status').innerHTML = '<span class="status-dot connected"></span> Connected & E2EE Secured 🔒';
                    
                    if (fileToSend) {
                        sendBtn.disabled = false;
                    }
                } catch (e) {
                    console.error("E2EE Handshake failed", e);
                }
            } else if (meta.type === 'file-start') {
                incomingFileInfo = meta;
                incomingFileData = [];
                receivedSize = 0;
                receivedChunks = 0;
                expectedChunks = meta.totalChunks || 0;
                decryptionQueue = Promise.resolve();
                console.log(`[RECEIVER] file-start: name=${meta.name}, size=${meta.size}, expectedChunks=${meta.totalChunks}`);
                
                progressContainer.classList.remove('hidden');
                downloadContainer.classList.add('hidden');
                progressText.innerText = 'Receiving...';
                updateProgress(0);
            } else if (meta.type === 'file-end') {
                console.log(`[RECEIVER] file-end received. Waiting for decryptionQueue to flush...`);
                decryptionQueue.then(() => {
                    console.log(`[RECEIVER] Queue flushed. Chunks stored: ${incomingFileData.length}, totalBytes: ${receivedSize}`);
                    saveReceivedFile();
                });
            }
        } else {
            // Binary data (Encrypted ArrayBuffer)
            // Queue chunk and wait for handshake to complete before decrypting
            decryptionQueue = decryptionQueue.then(async () => {
                await handshakePromise; // Wait for E2EE key derivation if not done yet
                try {
                    let payload;
                    if (data instanceof Blob) {
                        payload = new Uint8Array(await data.arrayBuffer());
                    } else {
                        // This safely handles ArrayBuffer and Uint8Array (including those with offsets)
                        payload = new Uint8Array(data);
                    }

                    console.log(`[RECEIVER] Binary chunk #${receivedChunks}: dataType=${data.constructor.name}, payloadBytes=${payload.length}`);

                    if (payload.length <= 12) {
                        console.error(`[RECEIVER] Chunk #${receivedChunks} too small to decrypt (${payload.length} bytes), skipping.`);
                        return;
                    }
                    
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
                    console.log(`[RECEIVER] Chunk #${receivedChunks} decrypted: ${decryptedChunk.byteLength} bytes, totalReceived=${receivedSize}`);
                    
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
        document.querySelector('.connection-status').innerHTML = '<span class="status-dot connected"></span> Connected to peer';
    });
}

// UI Handlers
joinBtn.addEventListener('click', () => {
    const roomId = roomInput.value.trim().toUpperCase();
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
    createRoom(newCode);
});

copyBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(generatedCodeSpan.innerText);
    copyBtn.innerText = '✓';
    setTimeout(() => { copyBtn.innerText = '📋'; }, 2000);
});

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
        fileToSend = e.target.files[0];
        selectedFileName.innerText = fileToSend.name;
        selectedFileName.style.display = 'block';
        uploadArea.querySelector('p').style.display = 'none';
        uploadArea.querySelector('svg').style.display = 'none';
        
        if (sharedCryptoKey) {
            sendBtn.disabled = false;
        }
    }
});

sendBtn.addEventListener('click', () => {
    if (fileToSend && dataConnection && dataConnection.open && sharedCryptoKey) {
        sendFile(fileToSend);
    }
});

// File Transfer Logic
function sendFile(file) {
    sendBtn.disabled = true;
    fileInput.disabled = true;
    progressContainer.classList.remove('hidden');
    progressText.innerText = 'Sending...';
    
    // Send meta with totalChunks so receiver can verify
    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
    console.log(`[SENDER] Starting transfer: name=${file.name}, size=${file.size}, totalChunks=${totalChunks}`);
    dataConnection.send(JSON.stringify({
        type: 'file-start',
        name: file.name,
        size: file.size,
        fileType: file.type,
        totalChunks: totalChunks
    }));

    let offset = 0;
    let chunkIndex = 0;
    const reader = new FileReader();
    
    reader.onerror = error => console.error('Error reading file:', error);
    reader.onabort = () => console.log('File reading aborted');
    
    reader.onload = async (e) => {
        const rawChunk = e.target.result;
        
        // Encrypt chunk
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        try {
            const encryptedChunk = await window.crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                sharedCryptoKey,
                rawChunk
            );
            
            // Append IV to encrypted data
            const payload = new Uint8Array(iv.length + encryptedChunk.byteLength);
            payload.set(iv, 0);
            payload.set(new Uint8Array(encryptedChunk), iv.length);

            console.log(`[SENDER] Sending chunk #${chunkIndex}: rawBytes=${rawChunk.byteLength}, payloadBytes=${payload.buffer.byteLength}`);
            // Send the ArrayBuffer directly for maximum PeerJS compatibility
            dataConnection.send(payload.buffer);
            chunkIndex++;
            
            offset += rawChunk.byteLength;
            const percentage = Math.round((offset / file.size) * 100);
            updateProgress(percentage);

            if (offset < file.size) {
                // Throttle slightly to prevent memory overwhelming on fast local networks with large files + encryption overhead
                setTimeout(() => readSlice(offset), 0);
            } else {
                console.log(`[SENDER] All ${chunkIndex} chunks sent. Sending file-end.`);
                dataConnection.send(JSON.stringify({ type: 'file-end' }));
                progressText.innerText = 'Sent successfully!';
                sendBtn.disabled = false;
                fileInput.disabled = false;
                
                setTimeout(() => {
                    progressContainer.classList.add('hidden');
                    resetFileSelection();
                }, 3000);
            }
        } catch (err) {
            console.error("Encryption failed", err);
        }
    };

    const readSlice = (o) => {
        // Apply backpressure if the WebRTC buffer is full (e.g. > 1MB)
        if (dataConnection.dataChannel && dataConnection.dataChannel.bufferedAmount > 1024 * 1024) {
            setTimeout(() => readSlice(o), 50);
            return;
        }

        const slice = file.slice(o, o + CHUNK_SIZE);
        reader.readAsArrayBuffer(slice);
    };

    readSlice(0);
}

function saveReceivedFile() {
    const blob = new Blob(incomingFileData, { type: incomingFileInfo.fileType });
    const url = URL.createObjectURL(blob);
    
    progressText.innerText = 'Received successfully!';
    downloadContainer.classList.remove('hidden');
    downloadLink.href = url;
    downloadLink.download = incomingFileInfo.name;
    downloadLink.innerText = `Download ${incomingFileInfo.name}`;
    
    fileInput.disabled = false;
    
    setTimeout(() => {
        progressContainer.classList.add('hidden');
        resetFileSelection();
    }, 5000);
}

function updateProgress(percentage) {
    progressBar.style.width = `${percentage}%`;
    progressPercentage.innerText = `${percentage}%`;
}

function showTransferSection() {
    roomSection.classList.remove('active');
    setTimeout(() => {
        roomSection.classList.add('hidden');
        transferSection.classList.remove('hidden');
        transferSection.classList.add('active');
    }, 400);
}

function resetFileSelection() {
    fileToSend = null;
    fileInput.value = '';
    selectedFileName.style.display = 'none';
    uploadArea.querySelector('p').style.display = 'block';
    uploadArea.querySelector('svg').style.display = 'block';
    sendBtn.disabled = true;
}

function resetTransferState() {
    joinBtn.disabled = false;
    resetFileSelection();
    progressContainer.classList.add('hidden');
    downloadContainer.classList.add('hidden');
    updateProgress(0);
    document.querySelector('.connection-status').innerHTML = '<span class="status-dot connected"></span> Connected to peer';
}
