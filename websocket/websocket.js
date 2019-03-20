const crypto = require('crypto');
const { EventEmitter } = require('events');
// 最长长度限制，超过此长度就进行分片处理
const MAX_FRAME_SIZE = 50;
//  RFC6455规范要求的
const MAGIC_STRING = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const MASK_KEY_LENGTH = 4;

const OPCODES = {
  CONTINUE: 0,
  TEXT: 1,
  BINARY: 2,
  CLOSE: 8,
  PING: 9,
  PONG: 10,
};

const hashWebSocketKey = key => {
  const sha1 = crypto.createHash('sha1');
  sha1.update(key + MAGIC_STRING, 'ascii');
  return sha1.digest('base64');
};

/**
 * 解掩码
 * @param maskBytes 掩码数据
 * @param data payload
 * @returns {Buffer}
 */
const unmask = function(maskBytes, data) {
  const length = data.length;
  var payload = Buffer.alloc(length);
  for (var i = 0; i < length; i++) {
    payload[i] = maskBytes[i % 4] ^ data[i];
  }
  return payload;
};

/**
 *
 * @param {number} opcode
 * @param {string|buffer} payload
 * @param {boolean} isFinal
 */
const encodeMessage = function(opcode, payload, isFinal = true) {
  const len = payload.length;
  let buffer;
  let byte1 = (isFinal ? 0x80 : 0x00) | opcode;

  if (len < 126) {
    // 数据长度0~125

    // 构建返回数据容器
    buffer = Buffer.alloc(2 + len); // 2：[FIN+RSV1/2/3+OPCODE](占1bytes) + [MASK+payload length](占1bytes)

    // 写入FIN+RSV1/2/3+OPCODE
    buffer.writeUInt8(byte1);

    // 从第二帧写入MASK+payload length
    buffer.writeUInt8(len, 1);

    // 从第三帧写入真实数据
    payload.copy(buffer, 2);
  } else if (len < 1 << 16) {
    // 数据长度126~65535
    buffer.Buffer.alloc(2 + 2 + len);
    buffer.writeUInt8(byte1);
    buffer.writeUInt8(126, 1);
    buffer.writeUInt16(len, 2);
    payload.copy(buffer, 4);
  } else {
    // 数据长度65536~..
    buffer.Buffer.alloc(2 + 8 + len);
    buffer.writeUInt8(byte1);
    buffer.writeUInt8(127, 1);
    buffer.writeUInt32(0, 2);
    buffer.writeUInt32(len, 6);
    payload.copy(buffer, 10);
  }
  return buffer;
};

class WebSocket extends EventEmitter {
  constructor(req, socket) {
    super();
    const resKey = hashWebSocketKey(req.headers['sec-websocket-key']);
    const resHeaders = [
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      'Sec-WebSocket-Accept: ' + resKey,
    ]
      .concat('', '')
      .join('\r\n');

    this.socket = socket;
    this.buffer = Buffer.alloc(0);
    this.closed = false;
    this.payloadFrames = Buffer.alloc(0);
    this.frameOpcode = 0;
    this.keepLiveTimer = null;

    // 握手，协议升级
    socket.write(resHeaders);

    socket.on('data', data => {
      this.buffer = Buffer.concat([this.buffer, data]);
      this.parseFrams();
    });

    /**
     * 异常断开
     */
    socket.on('error', error => {
      this.emit('error', error);
    });

    socket.on('close', err => {
      if (!this.closed) {
        this.emit('close');
        this.closed = true;
      }
    });
  }

  /*
   * 关闭连接函数
   */
  close(code, reason) {
    var opcode = OPCODES.CLOSE;
    var buffer;
    if (code) {
      buffer = Buffer.alloc(Buffer.byteLength(reason) + 2);
      buffer.writeUInt16BE(code, 0);
      buffer.write(reason, 2);
    } else {
      buffer = Buffer.alloc(0);
    }
    this._send(opcode, buffer);
    this.closed = true;
    // 关闭socket
    this.socket.end();
  }

  /**
   * 向客户端发送数据
   * @param {string|object} data
   */
  send(data) {
    const isBuffer = Buffer.isBuffer(data);
    let opcode;
    let payload = data;
    if (isBuffer) {
      opcode = OPCODES.BINARY;
    } else {
      opcode = OPCODES.TEXT;
      const isObject = typeof data === 'object';
      if (isObject) {
        payload = JSON.stringify(data);
      }
      payload = Buffer.from(payload);
    }
    this._send(opcode, payload);
  }

  keepLive(timeout = 10000) {
    this._send(OPCODES.PING, Buffer.from('ping'));
    if (!this.closed) {
      this.keepLiveTimer = setTimeout(() => this.keepLive(), timeout);
    }
  }

  /**
   * 处理接受的帧
   */
  parseFrams() {
    // buffer接受到的数据
    const buffer = this.buffer;
    // 数据默认从第三个字节开始，默认数据长度小于125
    let payloadIndex = 2;

    // 获取第一个帧，包含FIN和操作码（opcode）
    const byte1 = buffer.readUInt8(0);

    // 0：还有后续帧
    // 1：最后一帧
    const FIN = (byte1 >>> 7) & 0x1;

    // 获取操作码，后面会根据操作码处理数据
    const opcode = byte1 & 0x0f;

    if (!FIN) {
      // 不是最后一帧需要暂存当前的操作码，协议要求:
      // 必须要暂存第一帧的操作码
      // 分片编号  0  1 ...  N-2  N-1
      //   FIN    0  0 ...  0    1
      // opcode  !0  0 ...  0    0
      this.frameOpcode = opcode || this.frameOpcode;
    }

    // 获取掩码（MASK）和数据长度（payload length）
    let byte2 = buffer.readUInt8(1);

    // 定义“payload data”是否被添加掩码
    // 如果置1， “Masking-key”就会被赋值
    // 所有从客户端发往服务器的帧都会被置1
    let MASK = (byte2 >>> 7) & 0x1;

    // 获取数据长度
    let payloadLength = byte2 & 0x7f;

    let mask_key;

    if (payloadLength === 126) {
      // 大于126小于65536，那么后面两帧（字节）表示的是数据的长度，那么真实的数据就会后移两帧
      payloadLength = buffer.readUInt16BE(payloadIndex);

      // 真实数据后移2位
      payloadIndex += 2;
    } else if (payloadLength === 127) {
      // 大于等于65536，那么后面八帧（字节）表示的是数据的长度，数据最长为64位，但是数据太大就不好处理了，这里限制最大为32位
      // 所以第2-6帧的数据始终应该为0，真实数据的长度在6-10帧
      // 4：2-6帧的位置
      payloadLength = buffer.readUInt32BE(payloadIndex + 4);
      // 8：数据长度占据了8帧，真实数据就需要后移8帧
      payloadIndex += 8;
    }

    // 如果MASK位被置为1那么Mask_key将占据4位 MASK_KEY_LENGTH===4
    const maskKeyLen = MASK ? MASK_KEY_LENGTH : 0;

    // 如果当前接受到的数据长度小于发送的数据总长度加上协议头部的数据长度，表示数据没有接受完，暂不处理，需要等到所有数据都接受到后再处理
    if (buffer.length < payloadIndex + maskKeyLen + payloadLength) {
      return;
    }

    // 如果有掩码，那么在真实数据之前会有四帧的掩码key（Masking-key）
    let payload = Buffer.alloc(0);
    if (MASK) {
      // 获取掩码
      mask_key = buffer.slice(payloadIndex, payloadIndex + MASK_KEY_LENGTH);

      // 真实数据再次后移4位
      payloadIndex += MASK_KEY_LENGTH;

      // 有掩码需要解码，解码算法是规定死的。
      payload = unmask(mask_key, buffer.slice(payloadIndex));
    } else {
      // 没有掩码就直接截取数据
      payload = buffer.slice(payloadIndex);
    }

    // 可能是分片传输，需要缓存数据帧，等待所有帧接受完毕后再处理完整数据
    this.payloadFrames = Buffer.concat([this.payloadFrames, payload]);
    this.buffer = Buffer.alloc(0);

    // 数据接受完毕
    if (FIN) {
      const _opcode = opcode || this.frameOpcode;
      const payloadFrames = this.payloadFrames.slice(0);
      this.payloadFrames = Buffer.alloc(0);
      this.frameOpcode = 0;

      // 根据不同opcode处理成不同的数据
      this.processPayload(_opcode, payloadFrames);
    }
  }

  //   0x1 : text帧
  //   0x2 ： binary帧
  //   0x3-7 ： 为非控制帧而预留的
  //   0x8 ： 关闭握手帧
  //   0x9 ： ping帧
  //   0xA :  pong帧
  //   0xB-F ： 为非控制帧而预留的
  processPayload(opcode, payloadFrames) {
    switch (opcode) {
      case OPCODES.TEXT:
        // 处理纯文本
        const data = payloadFrames.toString('utf8');
        this.emit('message', data, opcode);
        break;
      case OPCODES.BINARY:
        // 二进制文件
        this.emit('message', payloadFrames, opcode);
        break;
      case OPCODES.PING:
        // 发送 pong 做响应
        this._send(OPCODES.PONG, payloadFrames);
        break;
      case OPCODES.PONG:
        // 不做处理
        console.log('server receive pong');
        break;
      case OPCODES.CLOSE:
        let code, reason;
        if (payloadFrames.length >= 2) {
          code = payloadFrames.readUInt16BE(0);
          reason = payloadFrames.toString('utf8', 2);
        }
        this.close(code, reason);
        this.emit('close', code, reason);
        break;
      default:
        this.close(1002, 'unhandle opcode:' + opcode);
    }
  }

  _send(opcode, payload) {
    let isSharSing = false;
    while (payload.length > MAX_FRAME_SIZE) {
      const _payload = payload.slice(0, MAX_FRAME_SIZE);
      payload = payload.slice(MAX_FRAME_SIZE);
      // 分片传输：isSharSing为false时表示第一帧，第一帧需要将数据的操作码置为非0
      this.socket.write(
        encodeMessage(isSharSing ? OPCODES.CONTINUE : opcode, _payload, false)
      );
      isSharSing = true;
    }
    // 分片传输时：操作码在之前（while循环中）已经设置了，这个地方就必须为0
    // 未分片传输：操作码为非0
    this.socket.write(
      encodeMessage(isSharSing ? OPCODES.CONTINUE : opcode, payload)
    );
  }
}
module.exports = WebSocket;
