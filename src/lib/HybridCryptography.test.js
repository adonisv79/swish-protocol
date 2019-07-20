const HybridCryptography = require('./HybridCryptography');
const hc = new HybridCryptography();

describe('HybridCryptography.validateSwhsHeader', () => {
    const headers = {};

    test('should ensure there is a valid header object', () => {
        try { hc.validateSwhsHeader() }
        catch (err) { expect(err.message).toMatch('HEADER_SWHS_OBJECT_INVALID');}
    });
    
    test('should ensure there is an swhs_action value in the header', () => {
        try { hc.validateSwhsHeader(headers) }
        catch (err) { expect(err.message).toMatch('HEADER_SWHS_ACTION_INVALID');}
    });
    
    test('should ensure there is an swhs_key value in the header', () => {
        headers.swhs_action = "something"
        try { hc.validateSwhsHeader(headers) }
        catch (err) { expect(err.message).toMatch('HEADER_SWHS_KEY_INVALID');}
    });
    
    test('should ensure there is an swhs_iv value in the header', () => {
        headers.swhs_key = "something"
        try { hc.validateSwhsHeader(headers) }
        catch (err) { expect(err.message).toMatch('HEADER_SWHS_IV_INVALID');}
    });

    test('should ensure there is an swhs_next value in the header', () => {
        headers.swhs_iv = "something"
        try { hc.validateSwhsHeader(headers); }
        catch (err) { expect(err.message).toMatch('HEADER_SWHS_NEXT_INVALID');}
    });

    test('should return true on success', () => {
        headers.swhs_next = "something"
        expect(hc.validateSwhsHeader(headers)).toBe(true);
    });
});

describe('HybridCryptography.aesEncrypt', () => {

    test('should ensure data is provided', () => {
        try { hc.aesEncrypt(); }
        catch (err) { expect(err.message).toMatch('DATA_IS_INVALID');}
    });

    test('should ensure data is provided', () => {
        try { hc.aesEncrypt({}); }
        catch (err) { expect(err.message).toMatch('KEY_IS_INVALID');}
    });

    test('should ensure data is provided', () => {
        try { hc.aesEncrypt({}, 'samplekey'); }
        catch (err) { expect(err.message).toMatch('IV_IS_INVALID');}
    });
});