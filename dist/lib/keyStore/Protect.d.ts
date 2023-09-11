import CryptoFactory from '../CryptoFactory';
import IKeyStore from './IKeyStore';
import { ProtectionFormat } from './ProtectionFormat';
/**
 * Class to model protection mechanisms
 */
export default class Protect {
    /**
     * Sign the payload
     * @param keyStorageReference used to reference the signing key
     * @param payload to sign
     * @param format Signature format
     * @param keyStore where to retrieve the signing key
     * @param cryptoFactory used to specify the algorithms to use
     * @param tokenHeaderParameters Header parameters in addition to 'alg' and 'kid' to be included in the header of the token.
     */
    static sign(keyStorageReference: string, payload: string, format: ProtectionFormat, keyStore: IKeyStore, cryptoFactory: CryptoFactory, tokenHeaderParameters?: {
        [name: string]: string;
    }): Promise<string>;
    /**
     * Decrypt the data with the key referenced by keyReference.
     * @param keyStorageReference Reference to the key used for signature.
     * @param cipher Data to decrypt
     * @param format Protection format used to decrypt the data
     * @param keyStore where to retrieve the signing key
     * @param cryptoFactory used to specify the algorithms to use
     * @returns The plain text message
     */
    static decrypt(keyStorageReference: string, cipher: string, format: ProtectionFormat, keyStore: IKeyStore, cryptoFactory: CryptoFactory): Promise<string>;
}
