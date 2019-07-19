import { default as HybridCryptography, SwhsHeaders, SwhsBody } from "./HybridCryptography";
import { BinaryLike } from "crypto";

export default class HandshakeServer extends HybridCryptography {

	constructor() {
		super();
	}

	/**
	 * Handles a handshake request from a new client
	 * @param headers - the request headers
	 * @param session_id - the unique session identifier
	 * @returns {{headers: {swhs_iv: *, swhs_action: string, swhs_sess_id: *, swhs_key: *, swhs_next: string}, body: {is_json: boolean, enc_body: string}, decrypt: {next_prv: CryptoKey, created_date: number}}}
	 */
	handleHandshakeRequest(headers: SwhsHeaders, session_id: string) {
		//validate the headers and ensure request is for handshake
		this.validateSwhsHeader(headers);
		if (headers.swhs_action !== 'handshake_init') {
			throw new Error("HANDSHAKE_INVALID: swhs_action is not handshake_init");
		}

		//first lets decrypt that public key for sending our responses to this client
		const response_pub_key = this.aesDecrypt(headers.swhs_next, false,
			headers.swhs_key, headers.swhs_iv);

		//encrypt an ok response using the client's response public key
		const result = this.encryptResponse(session_id, { status: 'ok' }, response_pub_key);

		result.headers.swhs_action = 'handshake_response'; //override the action value
		return result;
	}

	/**
	 * Decrypt the encrypted request with the session's next request decrypt key
	 * @param headers - the request headers
	 * @param req_body - the request body
	 * @param next_prv - the RSA private key used to decrypt the req_body
	 * @param passphrase - the Passphrase used to generate the RSA private key
	 * @returns {{next_pub: string, body: string}}
	 */
	decryptRequest(
		headers:SwhsHeaders, 
		body: SwhsBody, 
		next_prv: Buffer, 
		passphrase: string) {

		let decrypted = this.hybridDecrypt(body.enc_body,body.is_json,headers.swhs_next,
			next_prv,passphrase,headers.swhs_key,headers.swhs_iv);

		return {
			body: decrypted.data as any,
			next_pub: decrypted.next_pub
		};
	}


	/**
	 * Encrypt the response with the session public key
	 * @param swhs_sess_id - the unique session identifier
	 * @param body - the response body to encrypt
	 * @param rsa_pub - The RSA public key to be used to encrypt the data
	 * @returns {{headers: {swhs_iv: *, swhs_action: string, swhs_sess_id: *, swhs_key: *, swhs_next: string}, body: {is_json: boolean, enc_body: string}, decrypt: {next_prv: CryptoKey, created_date: number}}}
	 */
	encryptResponse(swhs_sess_id: string, body: BinaryLike | object, rsa_pub: Buffer | string) {
		if (!rsa_pub) {
			throw new Error('PUBLIC_KEY_INVALID')
		} else if (!body) {
			throw new Error('BODY_INVALID')
		}

		//use Hybrid Encryption and return the response in the proper structure
		const result = this.hybridEncrypt(body, rsa_pub);
		return {
			headers: {
				'swhs_sess_id': swhs_sess_id,
                'swhs_action': 'encrypt_response',
                'swhs_key': result.key,
                'swhs_iv': result.iv,
                'swhs_next': result.next_pub
			},
			body: {
				is_json: result.is_json,
				enc_body: result.enc_data
			},
			decrypt: {
				next_prv: result.next_prv,
                created_date: result.created_date
			}
		}
	}
};