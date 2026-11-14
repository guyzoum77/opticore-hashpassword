import {randomBytes, scrypt, timingSafeEqual} from "node:crypto";
import type {ScryptOptions} from "node:crypto";

// HashPasswordService has no scrypt algorithm (see HashAlgorithmType): this example hashes with Node's crypto.scrypt
// directly, with parameters above the OWASP minimum (N = 2^17, r = 8, p = 1: 128 MiB of memory), a new random salt
// per password and a constant-time comparison. Prefer the "argon2" algorithm of HashPasswordService.
const SCRYPT_OPTIONS: ScryptOptions = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };
const KEY_LENGTH: number = 64;

/**
 * Promise wrapper around crypto.scrypt with the example's parameters.
 */
function scryptAsync(password: string, salt: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject): void => {
        scrypt(password, salt, KEY_LENGTH, SCRYPT_OPTIONS, (error: Error | null, key: Buffer): void => {
            if (error) reject(error); else resolve(key);
        });
    });
}

async function main(): Promise<void> {
    const plainPassword: string = "correct horse battery staple";
    const salt: Buffer = randomBytes(16);

    const hash: Buffer = await scryptAsync(plainPassword, salt);
    // store the salt and the hash together, e.g. "salt$hash"
    const stored: string = `${salt.toString("hex")}$${hash.toString("hex")}`;
    console.log("Hashed password (scrypt):", stored);

    const [storedSalt, storedHash] = stored.split("$");
    const candidate: Buffer = await scryptAsync(plainPassword, Buffer.from(storedSalt, "hex"));
    const expected: Buffer = Buffer.from(storedHash, "hex");
    const isPasswordValid: boolean = candidate.length === expected.length && timingSafeEqual(candidate, expected);
    console.log("Is it a valid password?", isPasswordValid);
}

main().catch(console.error);
