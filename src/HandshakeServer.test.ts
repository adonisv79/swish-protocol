import { HandshakeServer } from "./HandshakeServer";
import { SwhsBody, SwhsHeaders } from "./HybridCryptography";

const server = new HandshakeServer();

describe("HybridCryptography.validateSwhsHeader", () => {
	const headers: SwhsHeaders = {
		swhs_action: "",
		swhs_iv: "",
		swhs_key: "",
		swhs_next: "",
		swhs_sess_id: "",
	};

	const body: SwhsBody = {
		enc_body: "",
		is_json: false,
	};

	test("should ensure there is a sessionId value to associate the session with", () => {
		try {
			server.handleHandshakeRequest(headers);
		} catch (err) {
			expect((err as Error).message).toMatch("SESSION_ID_INVALID");
		}
	});

	test("should ensure the swhs_action value is handshake_init", () => {
		try {
			headers.swhs_sess_id = "adonisv79";
			headers.swhs_action = "something";
			server.handleHandshakeRequest(headers);
		} catch (err) {
			expect((err as Error).message).toMatch("HANDSHAKE_INVALID_INIT");
		}
	});

	test("should ensure the swhs_iv is valid", () => {
		try {
			headers.swhs_sess_id = "adonisv79";
			headers.swhs_action = "handshake_init";
			server.handleHandshakeRequest(headers);
		} catch (err) {
			expect((err as Error).message).toMatch("HANDSHAKE_AES_IV_INVALID");
		}
	});
});
