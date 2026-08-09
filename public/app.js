const CHUNK_SIZE = 16000; // Strictly under 16KB (16384 bytes) to leave room for the 28-byte encryption overhead (IV + Auth Tag) so it doesn't break WebRTC limits on some devices

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

// File Receiving state
let incomingFileInfo = null;
let incomingFileData = [];
let receivedSize = 0;
let decryptionQueue = Promise.resolve();

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
    myKeyPair = await generateECDHKeyPair();
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
        const conn = tempPeer.connect(fullPeerId);
        
        conn.on('open', () => {
            roomStatus.innerText = 'Connected to peer! Negotiating E2EE...';
            setupConnection(conn);
            peer = tempPeer;
            showTransferSection();
            performHandshake(); // Initiate handshake
            
            peer.on('error', (err) => console.error(err));
        });
        
        conn.on('error', (err) => {
            tempPeer.destroy();
            createRoom(fullPeerId);
        });
        
        setTimeout(() => {
            if (!dataConnection) {
                conn.close();
                tempPeer.destroy();
                createRoom(fullPeerId);
            }
        }, 3000);
    });
}

function createRoom(fullPeerId) {
    roomStatus.innerText = 'Creating room... Waiting for peer to join.';
    peer = new Peer(fullPeerId);
    
    peer.on('open', (id) => {
        console.log('Room created with ID:', id);
    });
    
    peer.on('connection', (conn) => {
        if (dataConnection) {
            conn.close();
            return;
        }
        roomStatus.innerText = 'Peer joined! Negotiating E2EE...';
        setupConnection(conn);
        showTransferSection();
        performHandshake(); // Initiate handshake
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
                decryptionQueue = Promise.resolve();
                
                progressContainer.classList.remove('hidden');
                downloadContainer.classList.add('hidden');
                progressText.innerText = 'Receiving...';
                updateProgress(0);
            } else if (meta.type === 'file-end') {
                decryptionQueue.then(() => {
                    saveReceivedFile();
                });
            }
        } else {
            // Binary data (Encrypted ArrayBuffer)
            if (!sharedCryptoKey) return;
            
            decryptionQueue = decryptionQueue.then(async () => {
                try {
                    let payload;
                    if (data instanceof Blob) {
                        payload = new Uint8Array(await data.arrayBuffer());
                    } else {
                        // This safely handles ArrayBuffer and Uint8Array (including those with offsets)
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
                    receivedSize += decryptedChunk.byteLength;
                    
                    const percentage = Math.round((receivedSize / incomingFileInfo.size) * 100);
                    updateProgress(percentage);
                } catch (err) {
                    console.error("Decryption failed for a chunk", err);
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
    const roomId = roomInput.value.trim().toLowerCase();
    if (roomId.length > 0) {
        joinBtn.disabled = true;
        roomStatus.innerText = 'Connecting...';
        initPeer(roomId);
    }
});

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
    
    // Send meta (we send meta unencrypted for simplicity, but it could also be encrypted)
    dataConnection.send(JSON.stringify({
        type: 'file-start',
        name: file.name,
        size: file.size,
        fileType: file.type
    }));

    let offset = 0;
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
            
            // Send the Uint8Array directly, PeerJS handles TypedArrays perfectly
            dataConnection.send(payload);
            
            offset += rawChunk.byteLength;
            const percentage = Math.round((offset / file.size) * 100);
            updateProgress(percentage);

            if (offset < file.size) {
                // Throttle slightly to prevent memory overwhelming on fast local networks with large files + encryption overhead
                setTimeout(() => readSlice(offset), 0);
            } else {
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
