 """
  Sample file to test crypto scanner - contains quantum-vulnerable algorithms
  """

  from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
  from cryptography.hazmat.primitives import hashes
  from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
  from cryptography.hazmat.backends import default_backend
  import hashlib

  # RSA key generation - QUANTUM VULNERABLE (Shor's algorithm)
  private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048,  # Will be flagged as vulnerable
      backend=default_backend()
  )

  # ECDSA signing - QUANTUM VULNERABLE (Shor's algorithm)
  ec_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

  # DSA - QUANTUM VULNERABLE
  dsa_key = dsa.generate_private_key(key_size=2048, backend=default_backend())

  # AES-256 - Quantum-safe (Grover's reduces to 128-bit security)
  key = b'Thirty two byte key for AES256!!'
  cipher = Cipher(algorithms.AES(key), modes.GCM(b'12bytesIVval'), backend=default_backend())

  # SHA-256 - Quantum-safe (Grover's reduces to 128-bit security)
  hash_obj = hashlib.sha256(b"test data")

  # SHA-512 - Quantum-safe (better protection)
  hash_obj = hashlib.sha512(b"test data")

  Sample 2: JavaScript/Node.js with Mixed Crypto

  Create test_crypto.js:

  /**
   * Sample file to test crypto scanner - mixed quantum-vulnerable and safe algorithms
   */

  const crypto = require('crypto');
  const jwt = require('jsonwebtoken'); // If you have this package

  // RSA key generation - QUANTUM VULNERABLE
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048, // Will be flagged
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });

  // ECDSA key generation - QUANTUM VULNERABLE
  const ecKey = crypto.generateKeyPairSync('ec', {
    namedCurve: 'secp256k1' // Bitcoin curve - vulnerable
  });

  // EdDSA (Ed25519) - QUANTUM VULNERABLE
  const ed25519Key = crypto.generateKeyPairSync('ed25519');

  // AES-256-GCM - Quantum-safe
  const algorithm = 'aes-256-gcm';
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, key, iv);

  // SHA-256 hashing - Quantum-safe
  const hash = crypto.createHash('sha256');
  hash.update('some data');

  // HMAC with SHA-512 - Quantum-safe
  const hmac = crypto.createHmac('sha512', 'secret-key');

  Sample 3: TypeScript with Modern Crypto

  Create test_crypto.ts:

  /**
   * Sample TypeScript file with various crypto operations
   */

  import * as crypto from 'crypto';

  interface KeyPair {
    publicKey: string;
    privateKey: string;
  }

  // RSA-4096 - Still vulnerable but better than 2048
  function generateRSAKeyPair(): KeyPair {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 4096,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    return { publicKey, privateKey };
  }

  // ECDH key exchange - QUANTUM VULNERABLE
  const ecdh = crypto.createECDH('secp256k1');
  ecdh.generateKeys();

  // AES encryption - Quantum-safe
  function encryptData(data: string): Buffer {
    const algorithm = 'aes-256-gcm';
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);

    return Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
  }
