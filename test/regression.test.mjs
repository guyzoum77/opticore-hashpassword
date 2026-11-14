// Regression test: constant-time comparison in the PBKDF2-family branch — run with `npm run build && npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { generateKeyPairSync } from "node:crypto";

const require = createRequire(import.meta.url);
const { HashPasswordService } = require(process.env.OPTICORE_HASH_PATH ?? "../dist/index.cjs");
const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048, publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });

test("sha256 (PBKDF2) verification still accepts the right password and rejects a wrong one", async () => {
    const service = new HashPasswordService();
    const { hashedPassword, signedHash } = await service.hashPassword("Correct-Horse-9", "salt-salt-salt-salt", "sha512", 210000, 32, "hex", privateKey);
    assert.equal(await service.verifyHashPassword(hashedPassword, signedHash, "salt-salt-salt-salt", "Correct-Horse-9", "sha512", 210000, 32, "hex", publicKey), true);
    assert.equal(await service.verifyHashPassword(hashedPassword, signedHash, "salt-salt-salt-salt", "wrong-password", "sha512", 210000, 32, "hex", publicKey), false);
});

test("the comparison goes through crypto.timingSafeEqual", async () => {
    const crypto = require("node:crypto");
    const original = crypto.timingSafeEqual;
    let calls = 0;
    crypto.timingSafeEqual = (...args) => { calls += 1; return original(...args); };
    try {
        const service = new HashPasswordService();
        const { hashedPassword, signedHash } = await service.hashPassword("Correct-Horse-9", "salt-salt-salt-salt", "sha512", 210000, 32, "hex", privateKey);
        await service.verifyHashPassword(hashedPassword, signedHash, "salt-salt-salt-salt", "Correct-Horse-9", "sha512", 210000, 32, "hex", publicKey);
    } finally { crypto.timingSafeEqual = original; }
    assert.ok(calls >= 1);
});
