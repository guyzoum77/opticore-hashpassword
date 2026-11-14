# Hash Password Module

Requirements
------------
* Node.js >= 26.12.1

Installation
------------
<blockquote>npm i opticore-hashing-password</blockquote>

<p align="center">

<a href="https://github.com/opticore-hashpassword/actions?query=workflow%3ATests+branch%3Amaster"><img src="https://github.com/opticore-hashpassword/workflows/Tests/badge.svg?branch=master" alt="GitHub Actions Build Status"></a></p>


Usage
-------------
<blockquote>import {HashPasswordService} from "opticore-hashing-password";</blockquote>

Signatures:
```
hashPassword(password: string, salt: string, algorithm: HashAlgorithmType, iterations: number, keyLength: number,
             bufferEncoding: BufferEncoding | BinaryToTextEncoding, privateRSAKey: string,
             options?: HashPasswordOptions): Promise<any>

verifyHashPassword(storedHashedPassword: string, signedHashStored: any, storedSalt: any, providedPassword: string,
                   algorithm: HashAlgorithmType, iterations: number, keyLength: number,
                   bufferEncoding: BufferEncoding | BinaryToTextEncoding, publicRSAKey: string): Promise<boolean>
```
`HashAlgorithmType` is `"sha256" | "sha512" | "sha3-256" | "sha3-512" | "blake2b512" | "bcrypt" | "argon2"`.
For PBKDF2 (`sha*`, `blake2b512`) `hashPassword` resolves to `{ signedHash, hashedPassword }` (both `salt$hash`);
for `argon2` to `{ signedHash, hashedPassword }` and for `bcrypt` to `{ signedHash, hashPassword }`, where `signedHash`
is the RSA signature of the hash (made with `privateRSAKey`, checked with `publicRSAKey`).
When a parameter is refused, `hashPassword` logs the reason and resolves to `undefined`.

Exemple
-------------
```hash password
import { randomBytes } from "node:crypto";

const passwordHash: HashPasswordService = new HashPasswordService();
const plainPassword: string = "password";
const salt: string = randomBytes(16).toString("hex"); // a new random salt (>= 16 bytes) for each password
const hashAlgorithm = 'sha512';
const iterations = 210000; // minimum for sha512 / sha3-512 / blake2b512 (600000 for sha256 / sha3-256)
const keyLength = 64;      // bytes, minimum 16
```

```hash password
Hash password
const { hashedPassword, signedHash } = await passwordHash.hashPassword(plainPassword, salt, hashAlgorithm, iterations, keyLength, "hex", privateRSAKey);
```

```verify password
verify password
const isPasswordValid: boolean = await passwordHash.verifyHashPassword(hashedPassword, signedHash, salt, plainPassword, hashAlgorithm, iterations, keyLength, "hex", publicRSAKey);
```

```argon2
argon2 (argon2id): the salt argument is ignored, a random salt is generated and stored in the hash
const { hashedPassword, signedHash } = await passwordHash.hashPassword(plainPassword, salt, 'argon2', 2, 19456, "hex", privateRSAKey);
const isValid: boolean = await passwordHash.verifyHashPassword(hashedPassword, signedHash, null, plainPassword, 'argon2', 0, 0, "hex", publicRSAKey);
```

Notice
-------------
<blockquote>
You can use the RSA encrypt Password method, but you must first have an RSA key 
to pass it as a parameter. This method is not obligatory; 
it is just to increase the level of security
</blockquote>

<blockquote>
with argon2 as hash algorithm, `iterations` is the time cost and `keyLength` is the memory cost in KiB.
They are raised to at least 2 passes and 19456 KiB (19 MiB). Memory cost represents RAM, so if you exceed
your current RAM, your machine may crash, so be careful.
</blockquote>

Security
--------

### Breaking changes
* PBKDF2 (`sha256`, `sha512`, `sha3-256`, `sha3-512`, `blake2b512`): new hashes with too few iterations, a key length under 16 bytes or a salt under 16 bytes are refused (`hashPassword` resolves to `undefined`) unless `allowWeakParameters: true`. Calls with 100 or 1000 iterations no longer produce a hash. Existing hashes still verify with their original parameters.
* `verifyHashPassword` returns `false` for any algorithm other than the supported ones (e.g. `md5`, `sha1`): arbitrary digests are refused.
* bcrypt: passwords longer than 72 bytes (UTF-8) are refused by `hashPassword` and never match in `verifyHashPassword` (bcrypt would silently truncate them).
* argon2: the `salt` argument is ignored (a fresh random 16-byte salt is used and embedded in the hash) and the cost is raised to at least 19 MiB / 2 passes.
* RSA password encryption uses OAEP padding instead of PKCS#1 v1.5.
* Non-string passwords are refused (`hashPassword` resolves to `undefined`, `verifyHashPassword` returns `false`).

### Defaults and limits
PBKDF2 minimums for new hashes:

| Digest | Minimum iterations |
|---|---|
| `sha256`, `sha3-256` | 600 000 |
| `sha512`, `sha3-512`, `blake2b512` | 210 000 |

* Derived key length (`keyLength`): at least 16 bytes.
* Salt: at least 16 bytes, and must not contain the `$` separator. Use a new random salt for each password.
* PBKDF2 runs asynchronously (`crypto.pbkdf2`), so hashing and verification do not block the event loop.
* PBKDF2 hashes are compared in constant time (`crypto.timingSafeEqual`); malformed stored values return `false` instead of throwing.
* argon2 always uses argon2id, a random 16-byte salt, and at least `memoryCost` 19456 KiB and `timeCost` 2 (higher values passed by the caller are kept). The parameters are stored in the hash, so verification is not affected.
* bcrypt: at most 72 bytes of password.
* bcrypt / argon2: a tampered hash or signature, or an invalid public key, makes `verifyHashPassword` return `false` (it never throws).

### Opt-out option
`hashPassword` accepts an optional last argument `options: HashPasswordOptions` (exported type):

```
const legacy = await passwordHash.hashPassword(plainPassword, salt, 'sha256', 100000, 32, "hex", privateRSAKey, { allowWeakParameters: true });
```

* `allowWeakParameters: true` accepts PBKDF2 iteration counts, key lengths and salts below the minimums.

> **Warning:** weak PBKDF2 parameters make stolen hashes much cheaper to crack offline. Only use this option to keep a legacy system working while you migrate; it is never needed to verify existing hashes, which always verify with the parameters they were created with.

Security Issues
---------------
https://github.com/guyzoum77/opticore-hashing-password/issues

Contributing
------------
OptiCore Hash Password module is an Open Source, so if you would like to contribute, you're welcome. Clone repository and open pull request.

About
--------
OptiCore Hash Password module is led by **Guy-serge Kouacou** and supported by **Guy-serge Kouacou**

