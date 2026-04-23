const https = require('https');

const options = {
  hostname: 'mcp-preview.goskope.com', // Replace with the actual domain
  port: 443,
  path: '/',
  method: 'GET',
  // **ADD a standard User-Agent header**
  headers: {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
  }
};

const req = https.request(options, (res) => {
  console.log(`HTTP Status Code: ${res.statusCode}`);
  
  if (res.statusCode === 403) {
      console.error("🚫 Access Forbidden (403). The server rejected the request.");
      console.error("Try adding a 'User-Agent' header to mimic a browser.");
  }

  // Consume data to let the request complete
  res.on('data', () => {}); 

  res.on('end', () => {
    // Check if the socket is still available for details
    if (!res.socket) {
        // If 403 caused the immediate termination, this will still trigger
        console.error("❌ Socket details unavailable. Connection likely terminated by server after 403 response.");
        return; 
    }
    
    // SSL check logic (will only run if the socket object is still intact)
    const authorized = res.socket.authorized; 
    console.log(`✅ Connection to ${options.hostname} established.`);
    console.log(`Certificate Authorized: **${authorized}**`);
    
    // ... (rest of the certificate details logging)
  });
});

req.on('error', (e) => {
  console.error(`❌ Connection error: **${e.message}**`);
});

req.end();
