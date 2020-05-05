const crypto = require('crypto');   // a module to hash password

const sha1 = (msg) => crypto.createHash('sha1').update(msg, 'binary').digest('binary');
const xor = (buff1, buff2) => {   
	 var b1 = Buffer.from(buff1, 'binary');
	 var b2 = Buffer.from(buff2, 'binary');
	 var len = b1.length;
	 var result = Buffer.alloc(len);
	 for (let i = 0; i < len; i++) result[i] = b1[i] ^ b2[i];
	 return result;
};

const lenencValue = (data, offset) => { // see table 2 of the article	
	var len = data.readInt8(offset), end;
  //console.log("length: " + len);
  offset++;

	if (len === 251) return [null, offset];
	else if (len === 252 || len === 253)  {
		len = len - 250;		
		len = data.readIntLE(offset, len);			
	}	else {   
		// big integer (len = 8) not implemented			
	}
	end = offset + len;	
	return [data.toString('utf-8', offset, end), end]; 
} 	


module.exports = { sha1, xor, lenencValue };