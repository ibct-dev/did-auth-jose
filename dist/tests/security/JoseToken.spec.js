"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const JoseToken_1 = __importDefault(require("../../lib/security/JoseToken"));
const lib_1 = require("../../lib");
const Base64Url_1 = __importDefault(require("../../lib/utilities/Base64Url"));
class TestToken extends JoseToken_1.default {
    constructor(content) {
        super(content, TestToken.registry);
        if (content === 'token') {
            this.payload = content;
        }
    }
}
TestToken.registry = new lib_1.CryptoFactory([new lib_1.TestCryptoSuite()]);
describe('JoseToken', () => {
    describe('constructor', () => {
        it('should accept strings', () => {
            const token = new TestToken('foo');
            expect(token['content']).toEqual('foo');
        });
        it('should convert objects to JSON', () => {
            const fooObject = {
                test: 'foo'
            };
            const fooJson = JSON.stringify(fooObject);
            const token = new TestToken(fooObject);
            expect(token['content']).toEqual(fooJson);
        });
    });
    describe('getHeader', () => {
        it('should return protected and unprotected headers', () => {
            const token = new TestToken('token');
            token['protectedHeaders'] = Base64Url_1.default.encode(JSON.stringify({
                protectedHeader: 'foo'
            }));
            token['unprotectedHeaders'] = {
                unprotectedHeader: 'bar'
            };
            const headers = token.getHeader();
            expect(headers['unprotectedHeader']).toEqual('bar');
            expect(headers['protectedHeader']).toEqual('foo');
        });
        it('should return protected headers', () => {
            const token = new TestToken('token');
            token['protectedHeaders'] = Base64Url_1.default.encode(JSON.stringify({
                protectedHeader: 'foo'
            }));
            const headers = token.getHeader();
            expect(headers['protectedHeader']).toEqual('foo');
        });
        it('should return unprotected headers', () => {
            const token = new TestToken('token');
            token['unprotectedHeaders'] = {
                unprotectedHeader: 'bar'
            };
            const headers = token.getHeader();
            expect(headers['unprotectedHeader']).toEqual('bar');
        });
    });
    describe('getProtectedHeader', () => {
        it('should return protected headers', () => {
            const token = new TestToken('token');
            token['protectedHeaders'] = Base64Url_1.default.encode(JSON.stringify({
                protectedHeader: 'foo'
            }));
            const headers = token.getProtectedHeader();
            expect(headers['protectedHeader']).toEqual('foo');
        });
        it('should return empty if no protected headers are defined', () => {
            const token = new TestToken('token');
            const headers = token.getProtectedHeader();
            expect(headers).toEqual({});
        });
        it('should ignore unprotected headers', () => {
            const token = new TestToken('token');
            token['unprotectedHeaders'] = {
                unprotectedHeader: 'bar'
            };
            const headers = token.getProtectedHeader();
            expect(headers).toEqual({});
        });
    });
    describe('isContentWellFormedToken', () => {
        it('should return true if it was able to parse the token', () => {
            const token = new TestToken('token');
            expect(token.isContentWellFormedToken()).toBeTruthy();
        });
        it('should return false if it was unable to parse the token', () => {
            const token = new TestToken('not a token');
            expect(token.isContentWellFormedToken()).toBeFalsy();
        });
    });
});
//# sourceMappingURL=JoseToken.spec.js.map