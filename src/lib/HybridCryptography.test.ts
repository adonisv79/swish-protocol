import { default as HybridCryptography, SwhsHeaders } from "./HybridCryptography";
const hc = new HybridCryptography();

describe('HybridCryptography.validateSwhsHeader', () => {
    const headers: SwhsHeaders = {
        swhs_action: '01234567890123456789012345678901234567890123456789A',
        swhs_key: "",
        swhs_iv: "",
        swhs_next: "",
        swhs_sess_id: ""
    };
    
    test('should ensure there is an swhs_action value in the header', () => {
        try { hc.validateSwhsHeader(headers) }
        catch (err) { expect(err.message).toMatch('HEADER_SWHS_ACTION_LEN_ERR');}
    });
    
    test('should ensure there is an swhs_key value in the header', () => {
        headers.swhs_action = "something"
        try { hc.validateSwhsHeader(headers) }
        catch (err) { expect(err.message).toMatch('HEADER_SWHS_KEY_INVALID');}
    });
    
    // test('should ensure there is an swhs_iv value in the header', () => {
    //     headers.swhs_key = "something"
    //     try { hc.validateSwhsHeader(headers) }
    //     catch (err) { expect(err.message).toMatch('HEADER_SWHS_IV_INVALID');}
    // });

    // test('should ensure there is an swhs_next value in the header', () => {
    //     headers.swhs_iv = "something"
    //     try { hc.validateSwhsHeader(headers); }
    //     catch (err) { expect(err.message).toMatch('HEADER_SWHS_NEXT_INVALID');}
    // });

    // test('should return true on success', () => {
    //     headers.swhs_next = "something"
    //     expect(hc.validateSwhsHeader(headers)).toBe(true);
    // });
});

describe('HybridCryptography.aesEncrypt', () => {

    // test('should ensure data is provided', () => {
    //     try { hc.aesEncrypt(); }
    //     catch (err) { expect(err.message).toMatch('DATA_IS_INVALID');}
    // });

    // test('should ensure data is provided', () => {
    //     try { hc.aesEncrypt({}); }
    //     catch (err) { expect(err.message).toMatch('KEY_IS_INVALID');}
    // });

    // test('should ensure data is provided', () => {
    //     try { hc.aesEncrypt({}, 'samplekey'); }
    //     catch (err) { expect(err.message).toMatch('IV_IS_INVALID');}
    // });
});