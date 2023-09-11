/// <reference types="node" />
/**
 * Class for performing various Base64 URL operations.
 */
export default class Base64Url {
    /**
     * Encodes the input string or Buffer into a Base64URL string.
     */
    static encode(input: string | Buffer, encoding?: string): string;
    /**
     * Decodes a Base64URL string.
     */
    static decode(base64urlString: string, encoding?: string): string;
    /**
     * Decodes a Base64URL string
     */
    static decodeToBuffer(base64urlString: string): Buffer;
    /**
     * Converts a Base64URL string to a Base64 string.
     * TODO: Improve implementation perf.
     */
    static toBase64(base64UrlString: string): string;
    /**
     * Converts a Base64 string to a Base64URL string.
     * TODO: Improve implementation perf.
     */
    static fromBase64(base64String: string): string;
}
