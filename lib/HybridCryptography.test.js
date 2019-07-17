const HybridCryptography = require('./HybridCryptography');
const hc = new HybridCryptography();

// [undefined, null, [], "", 0].forEach((headers) => {
// });
describe('testing HybridCryptography.validateSwhsHeader', () => {

    test('validateSwhsHeader should ensure there is an object value', () => {
        try { hc.validateSwhsHeader() }
        catch (err) { expect(err.message).toMatch('HEADER_SWHS_OBJECT_INVALID');}
    });
    
    test('validateSwhsHeader should ensure there is an object value', () => {
        try { hc.validateSwhsHeader({}) }
        catch (err) { expect(err.message).toMatch('HEADER_SWHS_ACTION_INVALID');}
    });
    
});
