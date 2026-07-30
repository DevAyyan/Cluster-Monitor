const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8082;
const BACKEND_URL = process.env.BACKEND_URL || 'http://backend:5000';

// Proxy API requests (REST, SSE, OAuth) to Go backend
const apiProxy = createProxyMiddleware({
    target: BACKEND_URL,
    changeOrigin: true,
    ws: true
});

app.use('/api', apiProxy);

// Serve static frontend assets
app.use('/static', express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`[cluster-frontend] Dedicated Frontend Gateway running on http://0.0.0.0:${PORT} (Proxying /api -> ${BACKEND_URL})`);
});

// Forward WebSocket upgrade requests to the proxy
server.on('upgrade', apiProxy.upgrade);
