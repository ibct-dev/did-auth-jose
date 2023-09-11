import JoseToken from './JoseToken';
import PublicKey from '../security/PublicKey';
import { PrivateKey, CryptoFactory } from '..';
/**
 * JWS in flattened json format
 */
export declare type FlatJsonJws = {
    /** The protected (signed) header. */
    protected?: string;
    /** The unprotected (unverified) header. */
    header?: {
        [name: string]: string;
    };
    /** The application-specific payload. */
    payload: string;
    /** The JWS signature. */
    signature: string;
};
/**
 * Class for containing JWS token operations.
 * This class hides the JOSE and crypto library dependencies to allow support for additional crypto algorithms.
 */
export default class JwsToken extends JoseToken {
    protected cryptoFactory: CryptoFactory;
    private readonly signature;
    constructor(content: string | object, cryptoFactory: CryptoFactory);
    /**
     * Signs contents given at construction using the given private key in JWK format.
     *
     * @param jwsHeaderParameters Header parameters in addition to 'alg' and 'kid' to be included in the JWS.
     * @returns Signed payload in compact JWS format.
     */
    sign(jwk: PrivateKey, jwsHeaderParameters?: {
        [name: string]: string;
    }): Promise<string>;
    /**
     * Signs contents given at construction using the given private key in JWK format with additional optional header fields
     * @param jwk Private key used in the signature
     * @param options Additional protected and header fields to include in the JWS
     */
    signAsFlattenedJson(jwk: PrivateKey, options?: {
        protected?: {
            [name: string]: string;
        };
        header?: {
            [name: string]: string;
        };
    }): Promise<FlatJsonJws>;
    /**
     * Verifies the JWS using the given key in JWK object format.
     *
     * @returns The payload if signature is verified. Throws exception otherwise.
     */
    verifySignature(jwk: PublicKey): Promise<string>;
    /**
     * Gets the base64 URL decrypted payload.
     */
    getPayload(): any;
    /**
     * Converts the JWS from the constructed type into a Compact JWS
     */
    toCompactJws(): string;
    /**
     * Converts the JWS from the constructed type into a Flat JSON JWS
     * @param headers unprotected headers to use
     */
    toFlattenedJsonJws(headers?: {
        [member: string]: any;
    }): FlatJsonJws;
}
