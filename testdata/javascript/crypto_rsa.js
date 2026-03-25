const crypto = require('crypto');

// Generate RSA key pair - QUANTUM VULNERABLE
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
});

const message = Buffer.from('secret data');

// Encrypt with RSA - vulnerable
const encrypted = crypto.publicEncrypt(publicKey, message);

// Decrypt
const decrypted = crypto.privateDecrypt(privateKey, encrypted);

// Also using MD5 - weak hash
const hash = crypto.createHash('md5').update(message).digest('hex');
console.log(hash);

// SHA-1 - deprecated
const sha1 = crypto.createHash('sha1').update(message).digest('hex');
console.log(sha1);
