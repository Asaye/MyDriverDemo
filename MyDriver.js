const net = require('net'); // a module to create a socket
const { sha1, xor, lenencValue } = require('./Utils');
const TYPES = require('./types.json'); // a local file for column 
 
module.exports = class MyDriver {
   constructor() {
      this.socket = null;      // the socket instance
      this.config = null;      // client's configuration data
      this.callback = null;    // the active callback function
      this.isHandshake = true; // a flag which signals if a message
                               // is a handshake request or not 
      this.data = null;        // data received from the database
      this.queryQueue = [];    // queue of client queries 
      this.results = {         // result to be sent to the client
         fields: [], 
         rows: []
      };
      this.isReadyForQuery = false; // a flag which signals whether 
                                    // the database is ready to 
                                    // process the next query
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
close() {
   // to be implemented later
}

_addListeners() {
   this.socket.on("connect", (err) => { 
      this.callback(err, "Connection successful!");
   });   

   this.socket.on("data", (data) => { 
      
      if (this.isHandshake) {
          this._authenticate(data);
          this.isHandshake = false; 
      } else {
          this._parse(data);
      } 
   });
   this.socket.on("error", (err) => {
      this.callback(err);
   });
   this.socket.on("readyForQuery", () => { 
      if (this.queryQueue.length > 0) {
         // set the flag to false so that another query won't 
         // interrupt this one
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
   if (!data) return;
 
   var offset = data.indexOf(0, 5); // find index of null-terminator   
                                    // for the server version string 
  
   const auth1 = data.slice(offset + 5, offset + 13);  
   const L2 = data.readInt8(offset + 21);
   const auth2 = data.slice(offset + 32, offset + 32 + (L2 - 8));
   const auth_data = Buffer.concat([auth1, auth2]);
   const temp = offset + 32 + (L2 - 8);
   
   // find index of null-terminator for the auth method   
   offset = data.indexOf(0, temp + 1);  
   const auth_method = data.slice(temp, offset);
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
   // capablity flag of the client
   buffer.writeInt32LE(0x00000200 | 0x00020000 | 0x00000008, 4); 
   buffer.writeInt32LE(0, 8);  
   buffer.writeInt8(33, 12);   // 33 = charset code for utf-8
   buffer.write(this.config.user + "\0", 36, l_u + 1);
   buffer[37 + l_u] = pwd.length;
   pwd.copy(buffer, 38 + l_u);
   buffer.write(db + "\0", 38 + l_u + pwd.length, l_d); 
   buffer[38 + l_u + pwd.length + l_d] = 0;
   const l_temp = 39 + l_u + pwd.length + l_d;
   buffer.write(str + "\0", l_temp, str.length + 1);
   this.socket.write(buffer);
}
_parse(data) {
   
   const header = data.readInt8(4);  
   //console.log(header);
   if (header === 0 || header === 254) {    // 254 = 0xfe
      this.socket.emit('readyForQuery');
   } else if (header === 255) {             // 255 = 0xff
      this._error(data.slice(6));
   } else {
      //console.log(data.toString());
      this._resultSet(data);
   }
}
_error(data) {
   const code = data.readInt16LE(0);   
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
   buffer[4] = 3;      // header for COM_QUERY
   buffer.write(text, 5, text.length);
   this.socket.write(buffer);
}
_resultSet(data) {
   //console.log(data.toString());
   var offset = 0, encoded, colName, dataType;
   const len = data.readIntLE(offset, offset += 3);
   const sequenceId = data.readInt8(offset++);
   encoded = lenencValue(data, offset);   
   const nColumns = parseInt(encoded[0]); // number of columns
   offset = encoded[1];

   for (let i = 0; i < nColumns; i++) { // for each column      
      for (let j = 0; j < 6; j++) {     // for lenenc strings
         encoded = lenencValue(data, offset);
         
         if (j === 5) {   // index corresponds to physical col. name
            colName = encoded[0];
         }
         offset = encoded[1];
      }
      offset += 7;
      dataType = "0x" + data.toString('hex', offset, ++offset);
      this.results.fields.push({
         name: colName,
         type: TYPES[dataType]
      });      
     
      offset += 9;
   }
   
   offset += 9; // 5 (EOF_Packet payload + 3 (length) + 1 (seq. id) 
   var row, header, hasNext = offset < data.length;
   while(hasNext) {
      row = {};
      
      for (let i = 0; i < nColumns; i++) {
         encoded = lenencValue(data, offset);
         row[this.results.fields[i].name] = encoded[0];
         offset = encoded[1];
      }
   
      header = data[offset + 4];  // read the header
      if (header === 0xff) {  // reading row data failed
         offset += data.readIntLE(offset, 3);
         continue;
      } else {
         this.results.rows.push(row);
         offset += 4;  // length of EOF_Packet
      }
      if (data[offset] === 0xfe) {
         hasNext = false;
        this.callback(null, this.results);
      }   
   }
}
}