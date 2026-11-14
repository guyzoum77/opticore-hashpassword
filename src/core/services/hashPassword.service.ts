import colors from "ansi-colors";
import * as bcrypt from "bcrypt";
import * as argon2 from "argon2";
import crypto from "crypto";
import {HashContractAbstract} from "../abstract/hashContractAbstract";
import {HashAlgorithmType} from "../types/hashAlgorithm.type";
import {dateTimeFormattedUtils} from "../utils/dateTimeFormatted.utils";
import {BinaryToTextEncoding} from "node:crypto";
import {LogMessageCore} from "opticore-console-log-message";
import {constants} from "node:http2";
import {promisify} from "node:util";

const pbkdf2Async = promisify(crypto.pbkdf2);

/**
 * Minimum PBKDF2 iteration counts for NEW hashes (OWASP Password Storage Cheat Sheet: 600 000 for
 * HMAC-SHA-256, 210 000 for HMAC-SHA-512; SHA-3 / BLAKE2b are mapped by digest size).
 */
const MIN_PBKDF2_ITERATIONS: Readonly<Record<string, number>> = {
    "sha256": 600_000,
    "sha3-256": 600_000,
    "sha512": 210_000,
    "sha3-512": 210_000,
    "blake2b512": 210_000,
};
/** Minimum PBKDF2 derived key length (bytes) and salt length (bytes) for NEW hashes. */
const MIN_PBKDF2_KEY_LENGTH: number = 16;
const MIN_SALT_BYTES: number = 16;
/** Argon2id floor (OWASP): 19 MiB of memory, 2 passes. Parameters are embedded in the hash, so raising them never breaks verification. */
const MIN_ARGON2_MEMORY_KIB: number = 19_456;
const MIN_ARGON2_TIME_COST: number = 2;
/** bcrypt silently ignores every byte after the 72nd: longer passwords are refused instead of being truncated. */
const BCRYPT_MAX_PASSWORD_BYTES: number = 72;

/**
 * Options of hashPassword.
 * allowWeakParameters: accept PBKDF2 iteration counts, key lengths or salts below the minimums (legacy only).
 */
export interface HashPasswordOptions {
    allowWeakParameters?: boolean;
}

export class HashPasswordService extends HashContractAbstract {

    /**
     *
     * @param hashedPassword
     * @param privateKey
     * @protected
     */
    protected signHash(hashedPassword: any, privateKey: string): string {
        const sign: crypto.Sign = crypto.createSign("sha3-512");
        sign.update(hashedPassword);
        sign.end();
        return sign.sign(privateKey, "hex");
    }

    /**
     *
     * @param password
     * @param publicKey
     * @param bufferEncoding
     *
     * The method encryptPasswordRSA is encrypting the hashed password using the public RSA key.
     *
     * Return encrypted data or handled error if any parameters are not provided or are wrong
     */
    protected encryptPasswordRSA(password: string, publicKey: string, bufferEncoding: BufferEncoding): string {
        try {
            const buffer: Buffer = Buffer.from(password);
            const encrypted: Buffer = crypto.publicEncrypt(
                {
                    key: Buffer.from(publicKey),
                    // OAEP: PKCS#1 v1.5 encryption padding is vulnerable to Bleichenbacher padding-oracle attacks
                    // (and privateDecrypt rejects it by default since Node 18.19/20.11, CVE-2023-46809).
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                },
                buffer
            );

            return encrypted.toString(bufferEncoding);
        } catch (err: any) {
            console.log(`${colors.red(`✘`)} ${colors.bgRed(`[ ${colors.bold(`${colors.white("Crypto publicEncrypt error")}`)} ]`)} | ${dateTimeFormattedUtils()} | [ ${colors.red(`${colors.bold("Error occurring at publicEncrypt level")}`)} ] | [ ${colors.bold(`${err.name}`)} ] ${colors.red(`${err.stack}`)} - ${colors.red(`${err.message}`)} - [ ${colors.red(`${colors.bold(`HttpCode`)}`)} ] ${colors.red(`${colors.bold(`406`)}`)} `);
            return err.message;
        }
    }

    /**
     *
     * @param length
     * @param bufferEncoding
     *
     * The method generateSalt is generating a random salt for hashing.
     *
     * Return a strong pseudorandom data or handling an error and return the callback function
     */
    protected generateSalt(length: number, bufferEncoding: BufferEncoding): string {
        try {
            return crypto.randomBytes(length).toString(bufferEncoding);
        } catch (err: any) {
            console.log(`${colors.red(`✘`)} ${colors.bgRed(`[ ${colors.bold(`${colors.white("Crypto randomBytes error")}`)} ]`)} | ${dateTimeFormattedUtils()} | [ ${colors.red(`${colors.bold("Error occurring at randomBytes level")}`)} ] | [ ${colors.bold(`${err.name}`)} ] ${colors.red(`${err.stack}`)} - ${colors.red(`${err.message}`)} - [ ${colors.red(`${colors.bold(`HttpCode`)}`)} ] ${colors.red(`${colors.bold(` 406 `)}`)} `);
            return err.message;
        }
    }

    /**
     *
     * @param encryptedPassword
     * @param privateKey
     * @param bufferEncoding
     *
     * The method decryptPasswordRSA is decrypting the encrypted password using the private RSA key
     *
     * Return decrypted data or handled error if any parameters are not provided or are wrong
     */
    public decryptPasswordRSA(encryptedPassword: string, privateKey: string, bufferEncoding: BufferEncoding): string {
        let decrypted;
        try {
            const buffer: Buffer = Buffer.from(encryptedPassword, bufferEncoding);
            decrypted = crypto.privateDecrypt(privateKey, buffer);
        } catch (err: any) {
            console.log(`${colors.red(`✘`)} ${colors.bgRed(`[ ${colors.bold(`${colors.white("Crypto privateDecrypt error")}`)} ]`)} | ${dateTimeFormattedUtils()} | [ ${colors.red(`${colors.bold("Error occurring at privateDecrypt level")}`)} ] | [ ${colors.bold(`${err.name}`)} ] ${colors.red(`${err.stack}`)} - ${colors.red(`${err.message}`)} - [ ${colors.red(`${colors.bold(`HttpCode`)}`)} ] ${colors.red(`${colors.bold(`406`)}`)} `);
            return "";
        }

        return decrypted.toString(bufferEncoding);
    }


    /**
     *
     * @param password
     * @param salt
     * @param algorithm
     * @param iterations
     * @param keyLength
     * @param bufferEncoding
     *
     * When it comes to secure hash algorithms, especially for cryptographic purposes like password hashing, some are more secure and commonly recommended due to their resistance to attacks. Here is a list of some of the most secure hash algorithms:
     *
     * SHA-512 (Secure Hash Algorithm 512-bit): Part of the SHA-2 family, it produces a 512-bit hash value and is considered very secure.
     *
     * SHA-256 (Secure Hash Algorithm 256-bit): Also part of the SHA-2 family, it produces a 256-bit hash value and is widely used and secure.
     *
     * SHA-3 (Secure Hash Algorithm 3): The latest member of the Secure Hash Algorithm family, it offers different hash lengths like SHA-3-256, SHA-3-512, etc. It is designed to be more secure than SHA-2.
     *
     * BLAKE2: Faster than MD5, SHA-1, and SHA-2 while maintaining a similar level of security. It comes in variants like BLAKE2b (optimized for 64-bit platforms) and BLAKE2s (optimized for 8- to 32-bit platforms).
     *
     * Argon2: The winner of the Password Hashing Competition (PHC) in 2015. It is highly secure and designed specifically for hashing passwords.
     *
     * bcrypt: Based on the Blowfish cipher, bcrypt is a password-hashing function that includes a salt to protect against rainbow table attacks and can handle brute-force attacks through its computational cost parameter.
     *
     * scrypt: Designed to be both computationally intensive and memory-hard, which makes it more resistant to hardware-based brute-force attacks.
     *
     * The hashPassword method hashes the password according
     * to HashAlgorithmType digest algorithm (sha256, sha512, or sha1 ...)
     * with a specified number of iterations, key length, and a bufferEncoding
     *
     * Return data hashed or handled an any error
     * @param privateRSAKey
     * @param options
     *
     * Security rules for NEW hashes: PBKDF2 refuses fewer iterations than MIN_PBKDF2_ITERATIONS, a key length
     * below 16 bytes or a salt below 16 bytes (unless options.allowWeakParameters is true — verification of
     * existing hashes is never affected); PBKDF2 runs asynchronously (no event-loop blocking); argon2id always
     * uses a fresh random 16-byte salt (embedded in the hash, the `salt` argument is ignored) and at least
     * 19 MiB / 2 passes; bcrypt refuses passwords longer than 72 bytes (it would silently truncate them).
     */
    public async hashPassword(password: string, salt: string, algorithm: HashAlgorithmType, iterations: number,
                       keyLength: number, bufferEncoding: BufferEncoding | BinaryToTextEncoding, privateRSAKey: string,
                       options: HashPasswordOptions = {}): Promise<any> {
        if (typeof password !== "string") {
            return console.log(`${colors.red(`✘`)} | ${dateTimeFormattedUtils()} | [ ${colors.red("Invalid password")} ] the password must be a string`);
        }
        switch (algorithm) {
            case "sha256":
            case "sha512":
            case "sha3-256":
            case "sha3-512":
            case "blake2b512":
                {
                    const weakParameter: string | null = this.weakPbkdf2Parameter(algorithm, salt, iterations, keyLength);
                    if (weakParameter && options?.allowWeakParameters !== true) {
                        return console.log(`${colors.red(`✘`)} ${colors.bgRed(`${colors.bold(`${colors.white("Weak hash parameters")}`)}`)} | ${dateTimeFormattedUtils()} | [ ${colors.red(`${colors.bold(weakParameter)}`)} ] - [ ${colors.red(`${colors.bold(`HttpCode`)}`)} ] ${colors.red(`${colors.bold("406")}`)} `);
                    }
                    try {
                        const hash: string = (await pbkdf2Async(password, salt, iterations, keyLength, algorithm)).toString(bufferEncoding);
                        return { "signedHash": [salt, hash].join("$"), "hashedPassword": [salt, hash].join("$") };
                    } catch (error: any) {
                        return console.log(`${colors.red(`✘`)} ${colors.bgRed(`${colors.bold(`${colors.white("Hash algorithm error")}`)}`)} | ${dateTimeFormattedUtils()} | [ ${colors.red(`${colors.bold("Unsupported")}`)} ] | [ ${colors.bold("Unsupported hash")} ] ${colors.red("")} - [ ${colors.red(`${colors.bold(`HttpCode`)}`)} ] ${colors.red(`${colors.bold("406")}`)} `);
                    }
                }
            case "bcrypt":
                if (Buffer.byteLength(password, "utf8") > BCRYPT_MAX_PASSWORD_BYTES) {
                    return console.log(`${colors.red(`✘`)} | ${dateTimeFormattedUtils()} | [ ${colors.red("bcrypt")} ] passwords longer than ${BCRYPT_MAX_PASSWORD_BYTES} bytes are refused (bcrypt would silently truncate them)`);
                }
                try {
                    const dataEncrypted: string = await bcrypt.hash(password, await bcrypt.genSalt());
                    const signedHash: string = this.signHash(dataEncrypted, privateRSAKey);
                    return { "signedHash": signedHash, "hashPassword": dataEncrypted };
                } catch (err: any) {
                    return console.log(`${colors.red(`✘`)} ${colors.bgRed(`${colors.bold(`${colors.black("bcrypt Hashing error ")}`)}`)} | ${dateTimeFormattedUtils()} | [ ${colors.red(`${colors.bold("Error occurring at bcrypt level")}`)} ] - [ ${colors.red(`${err.code}`)} ] - ${colors.red(`${err.message}`)} - [ ${colors.red(`${colors.bold(`HttpCode`)}`)} ] ${colors.red(`${colors.bold("406")}`)} `);
                }
            case "argon2":
                try {
                    const passHashed: string = await argon2.hash(
                        password,
                        {
                            salt: crypto.randomBytes(MIN_SALT_BYTES),
                            timeCost: Math.max(Number(iterations) || 0, MIN_ARGON2_TIME_COST),
                            memoryCost: Math.max(Number(keyLength) || 0, MIN_ARGON2_MEMORY_KIB),
                            type: argon2.argon2id
                        }
                    );
                    const signedHash: string = this.signHash(passHashed, privateRSAKey);
                    return { "signedHash": signedHash, "hashedPassword": passHashed };
                } catch (e: any) {
                    switch (e.code) {
                        case "ERR_ASSERTION":
                            return console.log(e.message)
                        default:
                            return console.log(e.message)
                    }
                }
            default:
                return console.log(`${colors.red(`✘`)} ${colors.bgRed(`[ ${colors.bold(`${colors.white(" Unsupported hash ")}`)} ]`)} | ${dateTimeFormattedUtils()} | [ ${colors.red(`${colors.bold("Error occurring")}`)} ] | ${colors.red("the hash you entered is not supported, we suggest choosing valid hashes like SHA-256, Argon2 or others")} - [ ${colors.red(`${colors.bold(`HttpCode`)}`)} ] ${colors.red(`${colors.bold("406")}`)} `);
        }
    }

    /**
     *
     * @param storedHashedPassword
     * @param signedHashStored
     * @param storedSalt
     * @param providedPassword
     * @param algorithm
     * @param iterations
     * @param keyLength
     * @param bufferEncoding
     * @param publicRSAKey
     * The verifyPassword method takes the stored hashed password, stored salt, provided password, hash algorithm,
     * iterations, and key length as parameters.
     * It hashes the provided password with the stored salt and compares it to the stored hashed password,
     *
     * returning true if there is match, otherwise false.
     *
     */
    public async verifyHashPassword(storedHashedPassword: string, signedHashStored: any, storedSalt: any, providedPassword: string,
                                    algorithm: HashAlgorithmType, iterations: number, keyLength: number,
                                    bufferEncoding: BufferEncoding | BinaryToTextEncoding, publicRSAKey: string): Promise<boolean> {
        if (typeof providedPassword !== "string") {
            return false;
        }
        switch (algorithm) {
            case "bcrypt":
                if (!this.safeVerifySignedHash(storedHashedPassword, signedHashStored, publicRSAKey)) {
                    LogMessageCore.error(
                        "Algorithm signature error",
                        "Invalid signature",
                        "Signed hash is invalid",
                        constants.HTTP_STATUS_NOT_ACCEPTABLE
                    );
                    return false;
                } else {
                    // bcrypt ignores bytes after the 72nd: never let a longer password match on its prefix.
                    if (Buffer.byteLength(providedPassword, "utf8") > BCRYPT_MAX_PASSWORD_BYTES) return false;
                    try {
                        return await bcrypt.compare(providedPassword, storedHashedPassword);
                    } catch {
                        return false;
                    }
                }
            case "argon2":
                if (!this.safeVerifySignedHash(storedHashedPassword, signedHashStored, publicRSAKey)) {
                    LogMessageCore.error(
                        "Algorithm signature error",
                        "Invalid signature",
                        "Signed hash is invalid",
                        constants.HTTP_STATUS_NOT_ACCEPTABLE
                    );
                    return false;
                } else {
                    try {
                        return await argon2.verify(storedHashedPassword, providedPassword);
                    } catch {
                        return false;
                    }
                }
            case "sha256":
            case "sha512":
            case "sha3-256":
            case "sha3-512":
            case "blake2b512":
                try {
                    if (typeof signedHashStored !== "string") return false;
                    const separator: number = signedHashStored.lastIndexOf("$");
                    if (separator <= 0) return false;
                    const storedSalt: string = signedHashStored.slice(0, separator);
                    const storedHashedPassword: string = signedHashStored.slice(separator + 1);
                    if (storedHashedPassword.length === 0 || !Number.isSafeInteger(iterations) || iterations < 1
                        || !Number.isSafeInteger(keyLength) || keyLength < 1) {
                        return false;
                    }
                    const hash: string = (await pbkdf2Async(providedPassword, storedSalt, iterations, keyLength, algorithm)).toString(bufferEncoding);
                    // constant-time comparison: a plain === leaks, through timing, how many leading characters matched
                    const computed: Buffer = Buffer.from(hash);
                    const stored: Buffer = Buffer.from(storedHashedPassword);
                    return computed.length === stored.length && crypto.timingSafeEqual(computed, stored);
                } catch (error: any) {
                    console.log(`${colors.red(`✘`)} ${colors.bgRed(`[ ${colors.bold(`${colors.white("crypto pbkdf2 error")}`)} ]`)} | ${dateTimeFormattedUtils()} | [ ${colors.red(`${colors.bold("Error occurring at pbkdf2 level")}`)} ] | [ ${colors.bold(`${error.name}`)} ] - ${colors.red(`${error.message}`)} - [ ${colors.red(`${colors.bold(`HttpCode`)}`)} ] ${colors.red(`${colors.bold(`406`)}`)} `);
                    return false;
                }
            default:
                // unknown algorithm: never "verified"
                return false;
        }
    }

    /**
     *
     * @param algorithm
     * @param salt
     * @param iterations
     * @param keyLength
     * @protected
     *
     * Return a description of the first PBKDF2 parameter below the minimums, or null when all are strong enough.
     */
    protected weakPbkdf2Parameter(algorithm: string, salt: string, iterations: number, keyLength: number): string | null {
        const minIterations: number = MIN_PBKDF2_ITERATIONS[algorithm] ?? 600_000;
        if (!Number.isSafeInteger(iterations) || iterations < minIterations) {
            return `${algorithm} PBKDF2 needs at least ${minIterations} iterations`;
        }
        if (!Number.isSafeInteger(keyLength) || keyLength < MIN_PBKDF2_KEY_LENGTH) {
            return `PBKDF2 key length must be at least ${MIN_PBKDF2_KEY_LENGTH} bytes`;
        }
        if (typeof salt !== "string" || Buffer.byteLength(salt) < MIN_SALT_BYTES) {
            return `the salt must be at least ${MIN_SALT_BYTES} bytes long (use a random salt per password)`;
        }
        if (salt.includes("$")) {
            return `the salt must not contain the "$" separator`;
        }
        return null;
    }

    /**
     *
     * @param hashedPassword
     * @param signedHash
     * @param publicKey
     * @protected
     *
     * Same as verifySignedHash, but a malformed key or signature yields false instead of throwing.
     */
    protected safeVerifySignedHash(hashedPassword: any, signedHash: any, publicKey: string): boolean {
        try {
            if (typeof hashedPassword !== "string" || typeof signedHash !== "string" || !/^[0-9a-f]+$/i.test(signedHash)) {
                return false;
            }
            return this.verifySignedHash(hashedPassword, signedHash, publicKey);
        } catch {
            return false;
        }
    }

    /**
     *
     * @param hashedPassword
     * @param signedHash
     * @param publicKey
     * @protected
     */
    protected verifySignedHash(hashedPassword: any, signedHash: any, publicKey: string): boolean {
        const verify: crypto.Verify = crypto.createVerify("sha3-512");
        verify.update(hashedPassword);
        verify.end();
        return verify.verify(publicKey, signedHash, "hex");
    }
}