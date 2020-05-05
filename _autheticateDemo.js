/***
  This file is created to demonstrate the complete parsing of the
  _authenticate function in MyDriver class. Otherwise, it is not
  used within the project
**/

_authenticate(data) {
   if (!data) return;
 
   var packet, offset = 0, len, count = 0, end, scramble = [];
 
   var length = data.readIntLE(0, 3);   // length of the payload
   var sequenceId = data.readInt8(3);

   // the payload starts from here
   var protocolVersion = data.readInt8(4);
   offset = data.indexOf(0, 5);  // find index of null-terminator   
                                 // for the server version string
 
   var serverVersion = data.slice(5, offset);
   var threadId = data.readInt32LE(offset + 1);  // read 4 bytes
   var auth1 = data.slice(offset + 5, offset + 13); // auth part-1
   var capability1 = data.readInt16LE(offset + 14); //read 2 bytes
   var charset = data.readInt8(offset + 16);
   var statusFlags = data.readInt16LE(offset + 17);
   var capability2 = data.readInt16LE(offset + 19);
   var L2 = data.readInt8(offset + 21);
   var filler = data.slice(offset + 22, offset + 32);
   var auth2 = data.slice(offset + 32, offset + 32 + (L2 - 8));
   var temp = offset + 32 + (L2 - 8);
   
   // find index of null-terminator for the server version string   
   offset = data.indexOf(0, temp + 1);  
   var auth_method = data.slice(temp, offset);
   /** parsing initial handshake request complete **/

 var auth_data = Buffer.concat([auth1, auth2]);
 const sha1 = (msg) => crypto.createHash('sha1').update(msg, 'binary').digest('binary');
 const xor = (buff1, buff2) => {   
   var b1 = Buffer.from(buff1, 'binary');
   var b2 = Buffer.from(buff2, 'binary');
   var len = b1.length;
   var result = Buffer.alloc(len);
   for (let i = 0; i < len; i++) result[i] = b1[i] ^ b2[i];
   return result;
 }
 const pass = this.config.password;
 const left = sha1(pass);
 const right = sha1(auth_data.toString('binary') + sha1(sha1(pass)));

 const pwd = pass ? xor(right, left) : Buffer.alloc(0);
 
const len_user = this.config.user.length;
 const len_db = this.config.database.length;
len = 3 + 1 + 9 + 23 + len_user + 1 + 1 + pwd.length + len_db + 1 + 1 + auth_method.length + 1;
 const buffer = Buffer.alloc(len);
 buffer.writeIntLE(len - 3 - 1, 0, 3);
 buffer[3] = 0x1;
 buffer.writeInt32LE(0x00000200 | 0x00020000 | 0x00008000, 4); // capablity flag of the client
 buffer.writeInt32LE(0, 8); // max size of a command packet that the client wants to send to the server
 buffer.writeInt8(33, 12); // charset code for utf-8
 buffer.write(this.config.user + "\0", 36, len_user + 1);
 buffer[36 + len_user + 1] = pwd.length;
 pwd.copy(buffer, 37 + len_user + 1);
 buffer.write(this.config.database + "\0", 37 + len_user + 2 + pwd.length, len_db + 1); 
 buffer[37 + len_user + 2 + pwd.length + len_db + 1] = 0;
 buffer.write(auth_method + "\0", 37 + len_user + 2 + pwd.length + len_db + 2, auth_method.length + 1);
 this.socket.write(buffer);
 }