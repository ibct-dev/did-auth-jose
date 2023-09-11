/// <reference types="node" />
import { ProtectionFormat } from './ProtectionFormat';
import PrivateKey from '../security/PrivateKey';
import PublicKey from '../security/PublicKey';
import IKeyStore from './IKeyStore';
import CryptoFactory from '../CryptoFactory';
/**
 * Class defining methods and properties for a light KeyStore
 */
export default class KeyStoreMem implements IKeyStore {
    private store;
    /**
     * Returns the key associated with the specified
     * key identifier.
     * @param keyReference for which to return the key.
     * @param publicKeyOnly True if only the public key is needed.
     */
    get(keyReference: string, publicKeyOnly: boolean): Promise<Buffer | PrivateKey | PublicKey>;
    /**
     * Lists all keys with their corresponding key ids
     */
    list(): Promise<{
        [name: string]: string;
    }>;
    /**
     * Saves the specified key to the key store using
     * the key identifier.
     * @param keyIdentifier for the key being saved.
     * @param key being saved to the key store.
     */
    save(keyIdentifier: string, key: Buffer | PrivateKey | PublicKey): Promise<void>;
    /**
     * Sign the data with the key referenced by keyIdentifier.
     * @param keyReference for the key used for signature.
     * @param payload Data to sign
     * @param format used to protect the content
     * @param cryptoFactory used to specify the algorithms to use
     * @param tokenHeaderParameters Header parameters in addition to 'alg' and 'kid' to be included in the header of the token.
     * @returns The protected message
     */
    sign(keyReference: string, payload: string, format: ProtectionFormat, cryptoFactory: CryptoFactory, tokenHeaderParameters?: {
        [name: string]: string;
    }): Promise<string>;
    /**
     * Decrypt the data with the key referenced by keyReference.
     * @param keyReference Reference to the key used for signature.
     * @param cipher Data to decrypt
     * @param format Protection format used to decrypt the data
     * @param cryptoFactory used to specify the algorithms to use
     * @returns The plain text message
     */
    decrypt(keyReference: string, cipher: string, format: ProtectionFormat, cryptoFactory: CryptoFactory): Promise<string>;
}
