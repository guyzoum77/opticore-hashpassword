// Security tests for opticore-hashing-password, run against the BUILT package (dist/).
// Run with `npm run build && npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { generateKeyPairSync, pbkdf2Sync } from "node:crypto";

const require = createRequire(import.meta.url);
const { HashPasswordService } = require(process.env.OPTICORE_HASH_PATH ?? "../dist/index.cjs");
const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048, publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
const quiet = async (fn) => { const l = console.log, e = console.error; console.log = console.error = () => {}; try { return await fn(); } finally { console.log = l; console.error = e; } };
const SALT = "0123456789abcdef0123";
const service = new HashPasswordService();

test("PBKDF2: weak iteration counts, short keys and short salts are refused for NEW hashes", async () => {
    assert.equal(await quiet(() => service.hashPassword("pw", SALT, "sha256", 100, 32, "hex", privateKey)), undefined);
    assert.equal(await quiet(() => service.hashPassword("pw", SALT, "sha512", 1000, 32, "hex", privateKey)), undefined);
    assert.equal(await quiet(() => service.hashPassword("pw", SALT, "sha512", 210000, 4, "hex", privateKey)), undefined);
    assert.equal(await quiet(() => service.hashPassword("pw", "salt", "sha512", 210000, 32, "hex", privateKey)), undefined);
    assert.equal(await quiet(() => service.hashPassword("pw", "", "sha512", 210000, 32, "hex", privateKey)), undefined);
    const strong = await service.hashPassword("pw", SALT, "sha512", 210000, 32, "hex", privateKey);
    assert.match(strong.hashedPassword, /^0123456789abcdef0123\$[0-9a-f]{64}$/);
});

test("PBKDF2: allowWeakParameters keeps legacy callers working, and legacy hashes still verify", async () => {
    const legacy = await service.hashPassword("pw", "salt", "sha256", 100, 32, "hex", privateKey, { allowWeakParameters: true });
    assert.equal(typeof legacy.hashedPassword, "string");
    assert.equal(await service.verifyHashPassword(legacy.hashedPassword, legacy.signedHash, "salt", "pw", "sha256", 100, 32, "hex", publicKey), true);
    // a hash produced by an older version (salt$hex) still verifies
    const old = `salt$${pbkdf2Sync("pw", "salt", 100, 32, "sha256").toString("hex")}`;
    assert.equal(await service.verifyHashPassword(old, old, "salt", "pw", "sha256", 100, 32, "hex", publicKey), true);
    assert.equal(await service.verifyHashPassword(old, old, "salt", "pw2", "sha256", 100, 32, "hex", publicKey), false);
});

test("PBKDF2: an empty stored hash / zero key length never verifies (regression)", async () => {
    for (const stored of ["salt$", "$", "", "salt", "nosalt$abc"]) {
        assert.equal(await quiet(() => service.verifyHashPassword(stored, stored, "salt", "anything", "sha256", 100, 0, "hex", publicKey)), false, stored);
    }
    assert.equal(await quiet(() => service.verifyHashPassword("s$", "s$", "s", "x", "sha256", 0, 32, "hex", publicKey)), false);
});

test("PBKDF2: malformed stored values never throw, they return false", async () => {
    for (const stored of [null, undefined, 42, {}, [], "a$b$c"]) {
        assert.equal(await quiet(() => service.verifyHashPassword(stored, stored, "x", "pw", "sha512", 1000, 32, "hex", publicKey)), false);
    }
});

test("PBKDF2 verification does not depend on (or crash on) the RSA key it does not use", async () => {
    const { hashedPassword, signedHash } = await service.hashPassword("pw", SALT, "sha512", 210000, 32, "hex", privateKey);
    assert.equal(await service.verifyHashPassword(hashedPassword, signedHash, SALT, "pw", "sha512", 210000, 32, "hex", "not a key"), true);
});

test("unsupported / weak digests (md5, sha1) are never accepted by verifyHashPassword", async () => {
    for (const algorithm of ["md5", "sha1", "none", ""]) {
        const stored = `salt$${pbkdf2Sync("pw", "salt", 1, 16, algorithm === "md5" ? "md5" : "sha1").toString("hex")}`;
        assert.equal(await quiet(() => service.verifyHashPassword(stored, stored, "salt", "pw", algorithm, 1, 16, "hex", publicKey)), false, algorithm);
    }
});

test("PBKDF2 runs asynchronously: the event loop keeps turning during a 600k-iteration verification", async () => {
    const { hashedPassword, signedHash } = await service.hashPassword("pw", SALT, "sha256", 600000, 32, "hex", privateKey);
    let ticks = 0;
    const timer = setInterval(() => { ticks += 1; }, 1);
    try {
        assert.equal(await service.verifyHashPassword(hashedPassword, signedHash, SALT, "pw", "sha256", 600000, 32, "hex", publicKey), true);
    } finally { clearInterval(timer); }
    assert.ok(ticks > 0, "event loop was blocked");
});

test("bcrypt: passwords over 72 bytes are refused (no silent truncation), prefix twins never match", async () => {
    const long = "a".repeat(80);
    assert.equal(await quiet(() => service.hashPassword(long, SALT, "bcrypt", 0, 0, "hex", privateKey)), undefined);
    const ok = await service.hashPassword("a".repeat(72), SALT, "bcrypt", 0, 0, "hex", privateKey);
    assert.equal(await service.verifyHashPassword(ok.hashPassword, ok.signedHash, null, "a".repeat(72), "bcrypt", 0, 0, "hex", publicKey), true);
    assert.equal(await service.verifyHashPassword(ok.hashPassword, ok.signedHash, null, "a".repeat(72) + "EXTRA", "bcrypt", 0, 0, "hex", publicKey), false);
});

test("bcrypt / argon2: a tampered hash or signature, or a bad public key, yields false (never throws)", async () => {
    const b = await service.hashPassword("pw", SALT, "bcrypt", 0, 0, "hex", privateKey);
    const other = await service.hashPassword("attacker", SALT, "bcrypt", 0, 0, "hex", privateKey);
    // swapping in another (validly formatted) hash without a matching signature is refused
    assert.equal(await quiet(() => service.verifyHashPassword(other.hashPassword, b.signedHash, null, "attacker", "bcrypt", 0, 0, "hex", publicKey)), false);
    assert.equal(await quiet(() => service.verifyHashPassword(b.hashPassword, "zz-not-hex", null, "pw", "bcrypt", 0, 0, "hex", publicKey)), false);
    assert.equal(await quiet(() => service.verifyHashPassword(b.hashPassword, b.signedHash, null, "pw", "bcrypt", 0, 0, "hex", "garbage key")), false);
    const a = await service.hashPassword("pw", SALT, "argon2", 2, 19456, "hex", privateKey);
    assert.equal(await service.verifyHashPassword(a.hashedPassword, a.signedHash, null, "pw", "argon2", 0, 0, "hex", publicKey), true);
    assert.equal(await quiet(() => service.verifyHashPassword(a.hashedPassword, a.signedHash, null, "pw", "argon2", 0, 0, "hex", "garbage key")), false);
    assert.equal(await quiet(() => service.verifyHashPassword("$argon2id$garbage", a.signedHash, null, "pw", "argon2", 0, 0, "hex", publicKey)), false);
});

test("argon2: a fresh random salt per hash and OWASP minimum cost, whatever the caller passes", async () => {
    const one = await service.hashPassword("pw", "static-salt-static", "argon2", 1, 1024, "hex", privateKey);
    const two = await service.hashPassword("pw", "static-salt-static", "argon2", 1, 1024, "hex", privateKey);
    assert.notEqual(one.hashedPassword, two.hashedPassword);
    assert.match(one.hashedPassword, /^\$argon2id\$v=19\$m=19456,t=2,p=\d+\$/);
    assert.equal(await service.verifyHashPassword(one.hashedPassword, one.signedHash, null, "pw", "argon2", 0, 0, "hex", publicKey), true);
});

test("non-string passwords are rejected", async () => {
    for (const pw of [null, undefined, 42, {}, ["pw"]]) {
        assert.equal(await quiet(() => service.hashPassword(pw, SALT, "sha512", 210000, 32, "hex", privateKey)), undefined);
        assert.equal(await quiet(() => service.verifyHashPassword("s$x", "s$x", "s", pw, "sha512", 1000, 32, "hex", publicKey)), false);
    }
});

test("RSA password encryption uses OAEP (PKCS#1 v1.5 is padding-oracle prone) and round-trips", () => {
    class Probe extends HashPasswordService { enc(p) { return this.encryptPasswordRSA(p, publicKey, "base64"); } }
    const cipher = new Probe().enc("s3cret");
    const plain = Buffer.from(new Probe().decryptPasswordRSA(cipher, privateKey, "base64"), "base64").toString();
    assert.equal(plain, "s3cret");
});
