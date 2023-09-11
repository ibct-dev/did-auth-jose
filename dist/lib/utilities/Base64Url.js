"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/**
 * Class for performing various Base64 URL operations.
 */
class Base64Url {
    /**
     * Encodes the input string or Buffer into a Base64URL string.
     */
    static encode(input, encoding = 'utf8') {
        let inputBuffer;
        if (Buffer.isBuffer(input)) {
            inputBuffer = input;
        }
        else {
            inputBuffer = Buffer.from(input, encoding);
        }
        const base64String = inputBuffer.toString('base64');
        return Base64Url.fromBase64(base64String);
    }
    /**
     * Decodes a Base64URL string.
     */
    static decode(base64urlString, encoding = 'utf8') {
        return Base64Url.decodeToBuffer(base64urlString).toString(encoding);
    }
    /**
     * Decodes a Base64URL string
     */
    static decodeToBuffer(base64urlString) {
        const base64String = Base64Url.toBase64(base64urlString);
        return Buffer.from(base64String, 'base64');
    }
    /**
     * Converts a Base64URL string to a Base64 string.
     * TODO: Improve implementation perf.
     */
    static toBase64(base64UrlString) {
        return (base64UrlString + '==='.slice((base64UrlString.length + 3) % 4))
            .replace(/-/g, '+')
            .replace(/_/g, '/');
    }
    /**
     * Converts a Base64 string to a Base64URL string.
     * TODO: Improve implementation perf.
     */
    static fromBase64(base64String) {
        return base64String
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }
}
exports.default = Base64Url;
//# sourceMappingURL=Base64Url.js.map