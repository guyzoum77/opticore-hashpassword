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
                    padding: crypto.constants.RSA_PKCS1_PADDING,
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
     */
    public async hashPassword(password: string, salt: string, algorithm: HashAlgorithmType, iterations: number,
                       keyLength: number, bufferEncoding: BufferEncoding | BinaryToTextEncoding, privateRSAKey: string): Promise<any> {
        switch (algorithm) {
            case "sha256":
            case "sha512":
            case "sha3-256":
            case "sha3-512":
            case "blake2b512":
                try {
                    return new Promise((resolve, reject): void => {
                        const hash: string = crypto.pbkdf2Sync(password, salt, iterations, keyLength, algorithm).toString(bufferEncoding);
                        return resolve({ "signedHash": [salt, hash].join("$"), "hashedPassword": [salt, hash].join("$") });
                    });
                } catch (error: any) {
                    return console.log(`${colors.red(`✘`)} ${colors.bgRed(`${colors.bold(`${colors.white("Hash algorithm error")}`)}`)} | ${dateTimeFormattedUtils()} | [ ${colors.red(`${colors.bold("Unsupported")}`)} ] | [ ${colors.bold("Unsupported hash")} ] ${colors.red("")} - [ ${colors.red(`${colors.bold(`HttpCode`)}`)} ] ${colors.red(`${colors.bold("406")}`)} `);
                }
            case "bcrypt":
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
                            salt: Buffer.from(salt),
                            timeCost: iterations,
                            memoryCost: keyLength,
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
        const validSignedHash: boolean = this.verifySignedHash(storedHashedPassword, signedHashStored, publicRSAKey);
        switch (algorithm) {
            case "bcrypt":
                if (!validSignedHash) {
                    LogMessageCore.error(
                        "Algorithm signature error",
                        "Invalid signature",
                        "Signed hash is invalid",
                        constants.HTTP_STATUS_NOT_ACCEPTABLE
                    );
                    return false;
                } else {
                    return bcrypt.compare(providedPassword, storedHashedPassword);
                }
            case "argon2":
                if (!validSignedHash) {
                    LogMessageCore.error(
                        "Algorithm signature error",
                        "Invalid signature",
                        "Signed hash is invalid",
                        constants.HTTP_STATUS_NOT_ACCEPTABLE
                    );
                    return false;
                } else {
                    return argon2.verify(storedHashedPassword, providedPassword);
                }
            default:
                try {
                    const [storedSalt, storedHashedPassword] = signedHashStored.split("$");
                    const hash: string = crypto.pbkdf2Sync(providedPassword, storedSalt, iterations, keyLength, algorithm).toString(bufferEncoding);
                    return hash === storedHashedPassword;
                } catch (error: any) {
                    console.log(`${colors.red(`✘`)} ${colors.bgRed(`[ ${colors.bold(`${colors.white("crypto pbkdf2 error")}`)} ]`)} | ${dateTimeFormattedUtils()} | [ ${colors.red(`${colors.bold("Error occurring at pbkdf2 level")}`)} ] | [ ${colors.bold(`${error.name}`)} ] ${colors.red(`${error.stack}`)} - ${colors.red(`${error.message}`)} - [ ${colors.red(`${colors.bold(`HttpCode`)}`)} ] ${colors.red(`${colors.bold(`406`)}`)} `);
                    return false;
                }
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