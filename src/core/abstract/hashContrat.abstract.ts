import {HashAlgorithmType} from "../types/hashAlgorithm.type";

export abstract class HashContratAbstract {
    /**
     *
     * @param length
     * @param bufferEncoding
     */
    abstract generateSalt(length: number, bufferEncoding: BufferEncoding ): string;

    /**
     *
     * @param password
     * @param salt
     * @param algorithm
     * @param iterations
     * @param keyLength
     * @param bufferEncoding
     */
    abstract hashPassword(password: string, salt: string, algorithm: HashAlgorithmType,
                          iterations: number, keyLength: number,
                          bufferEncoding: BufferEncoding ): Promise<any>;

    /**
     *
     * @param password
     * @param publicKey
     * @param bufferEncoding
     */
    abstract encryptPasswordRSA(password: string, publicKey: string, bufferEncoding: BufferEncoding ): string;

    /**
     *
     * @param encryptedPassword
     * @param privateKey
     * @param bufferEncoding
     */
    abstract decryptPasswordRSA(encryptedPassword: string, privateKey: string, bufferEncoding: BufferEncoding ): string;

    /**
     *
     * @param fetchUserById
     * @param id
     * @param storedHashedPassword
     * @param storedSalt
     * @param providedPassword
     * @param algorithm
     * @param iterations
     * @param keyLength
     * @param bufferEncoding
     */
    abstract verifyHashPassword(storedHashedPassword: string, storedSalt: string, providedPassword: string,
                                algorithm: HashAlgorithmType, iterations: number, keyLength: number,
                                bufferEncoding: BufferEncoding ): Promise<boolean | void>;
}