#!/usr/bin/env node
// Probe a TLS endpoint and report the certificate chain Node sees, using whatever trust
// store Node is currently configured with (system roots + NODE_EXTRA_CA_CERTS). Handy for
// confirming that the Netskope bundle configured by configure_tools_* is actually in effect.
//
// Usage:
//   node check_ssl.js [host[:port]] [path]
//   node check_ssl.js mcp-preview.goskope.com
//   node check_ssl.js example.com:8443 /health
//
// Exit code: 0 if the TLS chain validated against the active trust store, 1 otherwise.

const https = require('https');
const tls = require('tls');

const target = process.argv[2] || 'mcp-preview.goskope.com';
const path = process.argv[3] || '/';
const [hostname, portStr] = target.split(':');
const port = portStr ? parseInt(portStr, 10) : 443;

const options = {
  hostname,
  port,
  path,
  method: 'GET',
  // Do NOT abort the TLS handshake on an untrusted cert — we want to inspect the chain and
  // report `authorized` ourselves rather than throw before we can see anything.
  rejectUnauthorized: false,
  headers: {
    'User-Agent':
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
      '(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
  },
};

console.log(`Connecting to https://${hostname}:${port}${path} ...`);
if (process.env.NODE_EXTRA_CA_CERTS) {
  console.log(`NODE_EXTRA_CA_CERTS = ${process.env.NODE_EXTRA_CA_CERTS}`);
} else {
  console.log('NODE_EXTRA_CA_CERTS is not set (using system roots only).');
}

const req = https.request(options, (res) => {
  const socket = res.socket;
  const authorized = socket.authorized;

  console.log(`\nHTTP status: ${res.statusCode}`);
  if (res.statusCode === 403) {
    console.error('Note: 403 Forbidden — the TLS layer still completed; cert info below is valid.');
  }

  console.log(`Certificate authorized by active trust store: ${authorized ? 'YES' : 'NO'}`);
  if (!authorized && socket.authorizationError) {
    console.log(`Authorization error: ${socket.authorizationError}`);
  }

  // Walk the presented chain from leaf to root.
  let cert = socket.getPeerCertificate(true);
  const seen = new Set();
  let depth = 0;
  console.log('\nPresented certificate chain (leaf -> root):');
  while (cert && Object.keys(cert).length && !seen.has(cert.fingerprint256)) {
    seen.add(cert.fingerprint256);
    const subj = cert.subject ? cert.subject.CN || JSON.stringify(cert.subject) : '(unknown)';
    const iss = cert.issuer ? cert.issuer.CN || JSON.stringify(cert.issuer) : '(unknown)';
    console.log(`  [${depth}] subject: ${subj}`);
    console.log(`      issuer:  ${iss}`);
    console.log(`      valid:   ${cert.valid_from}  ->  ${cert.valid_to}`);
    if (cert.issuerCertificate && cert.issuerCertificate !== cert) {
      cert = cert.issuerCertificate;
      depth++;
    } else {
      break;
    }
  }

  res.on('data', () => {});
  res.on('end', () => {
    process.exitCode = authorized ? 0 : 1;
  });
});

req.on('error', (e) => {
  console.error(`Connection error: ${e.message}`);
  process.exitCode = 1;
});

req.end();
