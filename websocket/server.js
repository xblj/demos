const http = require('http');
const fs = require('fs');
const WebSocket = require('./websocket');
const server = http.createServer(function(req, res) {
  const stream = fs.createReadStream(__dirname + '/index.html');
  stream.pipe(res);
});

// Upgrade请求处理
server.on('upgrade', callback);

function callback(req, socket, upgradeHead) {
  const ws = new WebSocket(req, socket, upgradeHead);
  ws.on('message', function(payload) {
    console.log('receive data:', payload.length);
    ws.send(getString(130));
  });

  ws.on('close', function(code, reason) {
    console.log('close:', code, reason);
  });
}

function getString(len) {
  let str = '';
  for (let i = 0; i < len; i++) {
    str += '2';
  }
  return str;
}

server.listen(8080, function() {
  console.log('http://localhost:8080');
});
