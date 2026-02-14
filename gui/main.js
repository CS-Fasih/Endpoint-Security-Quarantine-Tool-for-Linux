/**
 * main.js — Electron main process for the Sentinel GUI (refactored).
 *
 * Architectural fixes:
 *   Fix 2: Uses Node.js `net` module to connect to the daemon's UNIX
 *          domain socket instead of a TCP WebSocket.
 *   Fix 4: On connect, sends {"action":"sync_state"} to request the
 *          full quarantine manifest from the daemon.
 *
 * Protocol: newline-delimited JSON over UNIX stream socket.
 */

const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const net = require('net');

/* ── Constants ──────────────────────────────────────────────────────────── */

const SOCKET_PATH = '/var/run/sentinel_gui.sock';
const RECONNECT_MS = 3000;

/* ── State ──────────────────────────────────────────────────────────────── */

let mainWindow = null;
let client = null;   /* net.Socket connected to daemon */
let retryTimer = null;
let recvBuffer = '';     /* Accumulates partial reads for line framing */

/* ── Window creation ────────────────────────────────────────────────────── */

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1280,
        height: 800,
        minWidth: 900,
        minHeight: 600,
        title: 'Sentinel — Endpoint Security',
        backgroundColor: '#0d1117',
        icon: path.join(__dirname, 'renderer', 'icon.png'),
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
            sandbox: false,
        },
    });

    mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

/* ── UNIX domain socket connection to daemon ────────────────────────────── */

function connectDaemon() {
    /* Clean up any existing connection. */
    if (client) {
        try { client.destroy(); } catch (e) { /* ignore */ }
        client = null;
    }
    recvBuffer = '';

    client = net.createConnection({ path: SOCKET_PATH });

    client.on('connect', () => {
        console.log('[IPC] Connected to daemon via', SOCKET_PATH);
        sendToRenderer('ws-status', { connected: true });

        /* Fix 4: Request full quarantine state on connect. */
        sendToDaemon({ action: 'sync_state' });
    });

    client.on('data', (chunk) => {
        /*
         * Newline-delimited JSON framing.
         * Accumulate data and split on '\n' to handle partial reads.
         */
        recvBuffer += chunk.toString();
        const lines = recvBuffer.split('\n');

        /* Last element is either an empty string (complete messages) or
         * a partial message — keep it in the buffer. */
        recvBuffer = lines.pop() || '';

        for (const line of lines) {
            if (!line.trim()) continue;
            try {
                const payload = JSON.parse(line);
                console.log('[IPC] Event:', payload.event);
                sendToRenderer('alert', payload);
            } catch (err) {
                console.error('[IPC] Parse error:', err.message, 'raw:', line);
            }
        }
    });

    client.on('close', () => {
        console.log('[IPC] Disconnected — retrying in', RECONNECT_MS, 'ms');
        sendToRenderer('ws-status', { connected: false });
        client = null;
        scheduleReconnect();
    });

    client.on('error', (err) => {
        /* ENOENT: socket file doesn't exist yet (daemon not running).
         * ECONNREFUSED: daemon crashed.  Both trigger 'close' → reconnect. */
        if (err.code !== 'ENOENT' && err.code !== 'ECONNREFUSED') {
            console.error('[IPC] Error:', err.message);
        }
    });
}

function scheduleReconnect() {
    if (retryTimer) clearTimeout(retryTimer);
    retryTimer = setTimeout(() => {
        connectDaemon();
    }, RECONNECT_MS);
}

/**
 * Send a JSON object to the daemon over the UNIX socket.
 * Appends the newline delimiter automatically.
 */
function sendToDaemon(obj) {
    if (client && !client.destroyed) {
        client.write(JSON.stringify(obj) + '\n');
    }
}

function sendToRenderer(channel, data) {
    if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send(channel, data);
    }
}

/* ── IPC handlers (GUI renderer → Daemon) ───────────────────────────────── */

ipcMain.on('action', (_event, payload) => {
    /*
     * Forward user actions (restore / delete / sync_state) to the daemon.
     * Expected payload: { action: "restore"|"delete"|"sync_state", id: "..." }
     */
    if (client && !client.destroyed) {
        sendToDaemon(payload);
        console.log('[IPC] Sent action to daemon:', payload);
    } else {
        console.warn('[IPC] Daemon not connected — action dropped:', payload);
    }
});

/* ── App lifecycle ──────────────────────────────────────────────────────── */

app.whenReady().then(() => {
    createWindow();
    connectDaemon();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

app.on('window-all-closed', () => {
    if (client) { try { client.destroy(); } catch (e) { /* ignore */ } }
    if (retryTimer) clearTimeout(retryTimer);
    app.quit();
});
