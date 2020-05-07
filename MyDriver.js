const net = require('net');  // a module required to create a socket
const { sha1, xor, lenencValue, encLength } = require('./Util'); 
const TYPES = require('./types.json');

module.exports = class MyDriver {
   constructor() {
      this.socket = null;            // the socket instance
      this.config = null;            // client's configuration data
      this.callback = null;          // the active callback function
      this.queryQueue = [];          // queue of client queries  
      this.isHandshake = true;       // is a handshake request?
      this.isReadyForQuery = false;  // is the database is ready to 
                                     // process the next query?
   }

   connect(config, callback) { 
      this.config = config;
      this.callback = callback;
      this.socket = new net.Socket();
      this._addListeners();
      this.socket.connect(config.port, config.host); 
   }

   query(text, callback) { 
      // if the database server is ready for query and the queue is
      // empty, send the query directly. Otherwise, add the text and
      // callback to the queryQueue
      if (this.isReadyForQuery && this.queryQueue.length === 0) {
         // set the 'isReadyForQuery' flag to false so that another 
         // query won't interrupt this one
         this.isReadyForQuery = false; 
         this.callback = callback;
         this._send(text);
      } else {
         this.queryQueue.push({
            "text": text, 
            "callback": callback 
         });
      }
   }

   _addListeners() {
      this.socket.on("connect", (err) => { 
         this.callback(err, "Connection successful!");
      });   

      this.socket.on("data", (data) => { 
         if (this.isHandshake) {
             this._authenticate(data);
             this.isHandshake = false; //assumes authentication success
         } else {
             this._parse(data);
         } 
      });
      this.socket.on("error", (err) => {
         this.callback(err);
      });
      this.socket.on("readyForQuery", () => { 
         if (this.queryQueue.length > 0) {         
            this.isReadyForQuery = false;
            const next = this.queryQueue.shift(); 
            this.callback = next.callback;
            this._send(next.text);
         } else {
            this.isReadyForQuery = true;
         }
      });
   }

   _authenticate(data) { 
      var offset = data.indexOf(0, 5);  
      const auth1 = data.slice(offset + 5, offset + 13);
      const L2 = data.readUIntLE(offset + 21);
      const auth2 = data.slice(offset + 32, offset + 32 + (L2 - 9));
      var auth_data = Buffer.concat([auth1, auth2]);   
      var temp = offset +  32 + (L2 - 8);
      offset = data.indexOf(0, temp);  
      const auth_method = data.toString("utf-8", temp, offset);
      const pass = this.config.password;
      const left = sha1(pass);
      const str = auth_data.toString('binary');
      const right = sha1(str + sha1(sha1(pass)));
      const pwd = pass ? xor(right, left) : Buffer.alloc(0); 
      const l_u = this.config.user.length;
      const db = this.config.database;
      const l_d = db.length;
      const len = 41 + l_u + pwd.length + l_d + str.length;
      const buffer = Buffer.alloc(len);
      buffer.writeIntLE(len - 4, 0, 3);
      buffer[3] = 0x1;   
      buffer.writeInt32LE(0x00000200 | 0x00020000 | 0x00000008, 4); 
      buffer.writeInt32LE(0, 8);  
      buffer.writeInt8(33, 12);   
      buffer.write(this.config.user + "\0", 36, l_u + 1);
      buffer[37 + l_u] = pwd.length;
      pwd.copy(buffer, 38 + l_u);
      buffer.write(db + "\0", 38 + l_u + pwd.length, l_d); 
      buffer[38 + l_u + pwd.length + l_d] = 0;
      temp = 39 + l_u + pwd.length + l_d;
      buffer.write(auth_method + "\0", temp, auth_method.length + 1);
      this.socket.write(buffer);
   }

   _parse(data) {
      const header = data.readUInt8(4);  
      
      if (header === 0 || header === 254) {    // 254 = 0xfe
         this.socket.emit('readyForQuery');
      } else if (header === 255) {             // 255 = 0xff
         this._error(data.slice(5));
      } else {
         this._resultSet(data);
      }
   }

   _error(data) {      // based on Table 6
      const code = data.readUInt16LE(0);        
      const message = data.toString('utf-8', 8);
      this.callback({
         "code": code,
         "message": message 
      });  
   }

   _send(text) {
      const buffer = Buffer.alloc(3 + 1 + 1 + text.length);
      buffer.writeIntLE(1 + text.length, 0, 3);  // payload length
      buffer[3] = 0;      // sequence id
      buffer[4] = 3;      // header for COM_QUERY payload
      buffer.write(text, 5, text.length);
      this.socket.write(buffer);
   }

   _resultSet(data) {
      var offset = 4, nColumns; 
    
      [nColumns, offset] = encLength(data, offset);
      if (nColumns === 0) {                 // OK_Packet
         this.socket.emit('readyForQuery');
         return;
      }  
      this._columns(data, offset, nColumns); 
   }

   _columns(data, offset, nColumns) {
      var colName, dataType, header, temp;
      this.results = { fields: [] };
      for (let i = 0; i < nColumns; i++) { // for each column   
         offset += 4;       // 3 (length of next col.) + 1 (seq. id)
         for (let j = 0; j < 6; j++) {  // L1 - L6 [Table 8]
            [temp, offset] = lenencValue(data, offset);         
            if (j === 5) {   // index corresponds to physical col. name
               colName = temp;
            }
         }
         offset += 7;  // skip 7 bytes to point to data types(Table 8)
         dataType = "0x" + data.toString('hex', offset, ++offset);
         this.results.fields.push({
            "name": colName,
            "type": TYPES[dataType]      //TYPES - local json file
         });      
         
         offset += 5;    // 5 (remaining col. def. bytes)                   
      }
      offset += 13;      // 9 (EOF_Packet) + 3 (length) + 1 (seq. id)
      header = data[offset + 4];  // read the header
      if (header === 0xff) {  // reading rows failed
          this._error(data.slice(offset + 5));
          this.socket.emit('readyForQuery');
          return;
      }
      this._rows(data, offset);
   }

   _rows(data, offset) {
      var row, temp, hasNext = offset < data.length, 
          nColumns = this.results.fields.length;
      this.results.rows = [];
      while(hasNext) {
         row = {};
         
         for (let i = 0; i < nColumns; i++) {
            [temp, offset]= lenencValue(data, offset);
            row[this.results.fields[i].name] = temp;
         }
      
         this.results.rows.push(row);
         offset += 4;  // 3 (packet length) + 1 (seq. id)
         if (data[offset] === 0xfe) {
            hasNext = false;
            this.callback(null, this.results);
            this.socket.emit('readyForQuery');
         }   
      }
   }

   close(text) {
      const buffer = Buffer.alloc(3 + 1 + 1);
      buffer.writeIntLE(1, 0, 3);  // payload length
      buffer[3] = 0;               // sequence id
      buffer[4] = 1;               // header for COM_QUIT packet 
      this.socket.end(buffer);     // write + close
   }
}