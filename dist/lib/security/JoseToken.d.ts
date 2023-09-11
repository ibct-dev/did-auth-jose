import CryptoFactory from '../CryptoFactory';
/**
 * Base class for containing common operations for JWE and JWS tokens.
 * Not intended for creating instances of this class directly.
 */
export default abstract class JoseToken {
    protected cryptoFactory: CryptoFactory;
    /**
     * Content of the token
     */
    protected content: string;
    /**
     * Protected headers (base64url encoded)
     */
    protected protectedHeaders: string | undefined;
    /**
     * Unprotected headers
     */
    protected unprotectedHeaders: {
        [member: string]: any;
    } | undefined;
    /**
     * Payload (base64url encoded)
     */
    protected payload: string | undefined;
    /**
     * Constructor for JoseToken that takes in a compact-serialized token string.
     */
    constructor(content: string | object, cryptoFactory: CryptoFactory);
    /**
     * Gets the header as a JS object.
     */
    getHeader(): {
        [member: string]: any;
    };
    /**
     * Gets the protected headers as a JS object.
     */
    getProtectedHeader(): {
        [member: string]: any;
    };
    /**
     * Returns true if and only if the content was parsed as a token
     */
    isContentWellFormedToken(): boolean;
}
