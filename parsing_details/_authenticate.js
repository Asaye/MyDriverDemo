/***
  This file is created to demonstrate the complete parsing of the
  _authenticate function in MyDriver class. Otherwise, it is not
  used within the project
**/

_authenticate(data) {
   if (!data) return;
 
   var packet, offset = 0, len, count = 0, end, scramble = [];

   /*************** PACKET HEADER (4 bytes) ******************/

   var length = data.readIntLE(0, 3);   // length of the payload
   var sequenceId = data.readInt8(3);   // the sequence id

   /**************** PAYLOAD ********************************/
   var protocolVersion = data.readInt8(4);

   offset = data.indexOf(0, 5);  // find index of null-terminator for the server version string from  
                                 // index 5 = 3bytes (length) + 1byte(sequence id) + 1byte(protocol version)
 
   var serverVersion = data.slice(5, offset);       // slice the server version based on the bounding indices
   var threadId = data.readInt32LE(offset + 1);     // read 4 bytes starting just after the previous null-terminator
   var auth1 = data.slice(offset + 5, offset + 13); // auth part-1 - 8bytes of string
   var capability1 = data.readInt16LE(offset + 14); // read 2 bytes
   var charset = data.readInt8(offset + 16);        // read 1 byte
   var statusFlags = data.readInt16LE(offset + 17); // read 2 bytes
   var capability2 = data.readInt16LE(offset + 19); // read 2 bytes
   var L2 = data.readInt8(offset + 21);             // read 1 bytes - length of the auth-data = 12
   var filler = data.slice(offset + 22, offset + 32); // read 10bytes filler
   var auth2 = data.slice(offset + 32, offset + 32 + (L2 - 9)); // auth part-2, L2 - 9 is used as L2 includes 
                                                                // the additional null-terminator
   var temp = offset + 32 + (L2 - 8);
   
   // find index of null-terminator for the server version string   
   offset = data.indexOf(0, temp);                  // temp  = the start index of the auth_method
                                                    // the null-terminator may not exist in some versions due to a bug
                                                    // in that case just read the auth_method as string<EOF>
   var auth_method = data.slice(temp, offset);      // slice the auth method based on the bounding
   /** parsing initial handshake request complete **/ 
}