/// <reference types="node" />
import { IDidResolver } from '@decentralized-identity/did-common-typescript';
import PrivateKey from './security/PrivateKey';
import CryptoSuite from './interfaces/CryptoSuite';
import VerifiedRequest from './interfaces/VerifiedRequest';
import AuthenticationRequest from './interfaces/AuthenticationRequest';
import AuthenticationResponse from './interfaces/AuthenticationResponse';
import IKeyStore from './keyStore/IKeyStore';
/**
 * Named arguments to construct an Authentication object
 */
export interface AuthenticationOptions {
    /** An object with the did document key id mapping to private keys */
    keys?: {
        [name: string]: PrivateKey; 
    };
    /** A dictionary with the did document key id mapping to private key references in the keystore */
    keyReferences?: string[];
    /** The keystore */
    keyStore?: IKeyStore;
    /** DID Resolver used to retrieve public keys */
    resolver: IDidResolver;
    /** Optional parameter to customize supported CryptoSuites */
    cryptoSuites?: CryptoSuite[];
    /** Optional parameter to change the amount of time a token is valid in minutes */
    tokenValidDurationInMinutes?: number;
}
/**
 * Class for decrypting and verifying, or signing and encrypting content in an End to End DID Authentication format
 */
export default class Authentication {
    /** DID Resolver used to retrieve public keys */
    private resolver;
    /** The amount of time a token is valid in minutes */
    private tokenValidDurationInMinutes;
    /** Private keys of the authentication owner */
    private keys?;
    /** Reference to Private keys of the authentication owner */
    private keyReferences?;
    /** The keystore */
    private keyStore;
    /** Factory for creating JWTs and public keys */
    private factory;
    /**
     * Authentication constructor
     * @param options Arguments to a constructor in a named object
     */
    constructor(options: AuthenticationOptions);
    /**
     * Signs the AuthenticationRequest with the private key of the Requester and returns the signed JWT.
     * @param request well-formed AuthenticationRequest object
     * @returns the signed compact JWT.
     */
    signAuthenticationRequest(request: AuthenticationRequest): Promise<string>;
    /**
     * Verifies signature on request and returns AuthenticationRequest.
     * @param request Authentiation Request as a buffer or string.
     */
    verifyAuthenticationRequest(request: Buffer | string): Promise<AuthenticationRequest>;
    /**
     * Given a challenge, forms a signed response using a given DID that expires at expiration, or a default expiration.
     * @param authRequest Challenge to respond to
     * @param responseDid The DID to respond with
     * @param claims Claims that the requester asked for
     * @param expiration optional expiration datetime of the response
     * @param keyReference pointing to the signing key
     */
    formAuthenticationResponse(authRequest: AuthenticationRequest, responseDid: string, claims: any, expiration?: Date): Promise<string>;
    /**
     * Return a reference to the private key that was passed by caller.
     * If the key was passed in by value, it will be stored in the store and a reference is returned
     * @param iss Issuer identifier
     */
    private getKeyReference;
    /**
     * Private method that gets the private key of the DID from the key mapping.
     * @param did the DID whose private key is used to sign JWT.
     * @returns private key of the DID.
     */
    private getKey;
    /**
     * helper method that verifies the signature on jws and returns the payload if signature is verified.
     * @param jwsToken signed jws token whose signature will be verified.
     * @returns the payload if jws signature is verified.
     */
    private verifySignature;
    /**
     * Verifies the signature on a AuthenticationResponse and returns a AuthenticationResponse object
     * @param authResponse AuthenticationResponse to verify as a string or buffer
     * @returns the authenticationResponse as a AuthenticationResponse Object
     */
    verifyAuthenticationResponse(authResponse: Buffer | string): Promise<AuthenticationResponse>;
    /**
     * Given a JOSE Authenticated Request, will decrypt the request, resolve the requester's did, and validate the signature.
     * @param request The JOSE Authenticated Request to decrypt and validate
     * @param accessTokenCheck Check the validity of the access token
     * @returns The content of the request as a VerifiedRequest, or a response containing an access token
     */
    getVerifiedRequest(request: Buffer, accessTokenCheck?: boolean): Promise<VerifiedRequest | Buffer>;
    /**
     * Given the verified request, uses the same keys and metadata to sign and encrypt the response
     * @param request The original JOSE Verified Request request
     * @param response The plaintext response to be signed and encrypted
     * @returns An encrypted and signed form of the response
     */
    getAuthenticatedResponse(request: VerifiedRequest, response: string): Promise<Buffer>;
    /**
     * Creates an encrypted and authenticated JOSE request
     * @param content the content of the request
     * @param privateKey the private key to sign with
     * @param recipient the DID the request is indended for
     * @param accessToken an access token to be used with the other party
     */
    getAuthenticatedRequest(content: string, recipient: string, accessToken?: string): Promise<Buffer>;
    /**
     * Given a JWE, retrieves the PrivateKey to be used for decryption
     * @param jweToken The JWE to inspect
     * @returns The PrivateKey corresponding to the JWE's encryption
     */
    private getPrivateKeyForJwe;
    /**
     * Retrieves the PublicKey used to sign a JWS
     * @param request the JWE string
     * @returns The PublicKey the JWS used for signing
     */
    private getPublicKey;
    /**
     * Retrieves the nonce from the JWS
     * @param jwsToken The JWS containing the nonce
     * @returns The nonce
     */
    private getRequesterNonce;
    /**
     * Forms a JWS using the local private key and content, then wraps in JWE using the requesterKey and nonce.
     * @param nonce Nonce to be included in the response
     * @param requesterkey PublicKey in which to encrypt the response
     * @param content The content to be signed and encrypted
     * @returns An encrypted and signed form of the content
     */
    private signThenEncryptInternal;
    /**
     * Creates a new access token and wrap it in a JWE/JWS pair.
     * @param subjectDid the DID this access token is issue to
     * @param nonce the nonce used in the original request
     * @param issuerKeyReference A reference to the key used in the original request
     * @param requesterKey the requesters key to encrypt the response with
     * @returns A new access token
     */
    private issueNewAccessToken;
    /**
     * Creates an access token for the subjectDid using the privateKey for the validDurationInMinutes
     * @param subjectDid The did this access token is issued to
     * @param privateKeyReference The private key used to generate this access token
     * @param validDurationInMinutes The duration this token is valid for, in minutes
     * @returns Signed JWT in compact serialized format.
     */
    private createAccessToken;
    /**
     * Verifies:
     * 1. JWT signature.
     * 2. Token's subject matches the given requeter DID.
     * 3. Token is not expired.
     *
     * @param publicKey Public key used to verify the given JWT in JWK JSON object format.
     * @param signedJwtString The signed-JWT string.
     * @param expectedRequesterDid Expected requester ID in the 'sub' field of the JWT payload.
     * @returns true if token passes all validation, false otherwise.
     */
    private verifyJwt;
}
