"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const PublicKey_1 = __importDefault(require("./PublicKey"));
/**
 * Represents a Private Key in JWK format.
 * @class
 * @abstract
 * @hideconstructor
 */
class PrivateKey extends PublicKey_1.default {
    constructor() {
        super(...arguments);
        /** Default Sign Algorithm for JWS 'alg' field */
        this.defaultSignAlgorithm = 'none';
    }
}
exports.default = PrivateKey;
//# sourceMappingURL=PrivateKey.js.map