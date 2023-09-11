import RsaPublicKey from './RsaPublicKey';
import PrivateKey from '../../security/PrivateKey';
import PublicKey from '../../security/PublicKey';
import { IDidDocumentPublicKey } from '@decentralized-identity/did-common-typescript';
/**
 * Represents Other primes info (RFC7518 6.3.2.7)
 */
declare type OtherPrime = {
    r: string;
    d: string;
    t: string;
};
/**
 * Represents an Rsa private key
 * @class
 * @extends PrivateKey
 */
export default class RsaPrivateKey extends RsaPublicKey implements PrivateKey {
    readonly defaultSignAlgorithm: string;
    /** Private exponent as specified by RFC7518 6.3.2.1 */
    d: string;
    /** First prime factor as specified by RFC7518 6.3.2.2 */
    p?: string;
    /** Second prime factor as specified by RFC7518 6.3.2.3 */
    q?: string;
    /** First factor CRT exponent as specified by RFC7518 6.3.2.4 */
    dp?: string;
    /** Second factor CRT exponent as specified by RFC7518 6.3.2.5 */
    dq?: string;
    /** First CRT coefficent as specified by RFC7518 6.3.2.6 */
    qi?: string;
    /** Other primes info as specified by RFC7518 6.3.2.7 */
    oth?: OtherPrime[];
    /**
     * Constructs a private key given a Did Document public key object containing additional private key
     * information
     * @param key public key object with additional private key information
     */
    constructor(key: IDidDocumentPublicKey);
    /**
     * Wraps a rsa private key in jwk format into a Did Document public key object with additonal information
     * @param kid Key ID
     * @param jwk JWK of the private key
     */
    static wrapJwk(kid: string, jwk: any): RsaPrivateKey;
    /**
     * Generates a new private key
     * @param kid Key ID
     */
    static generatePrivateKey(kid: string): Promise<RsaPrivateKey>;
    getPublicKey(): PublicKey;
}
export {};
