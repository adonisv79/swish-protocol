import { HandshakeServer } from './HandshakeServer';
import { SwishBody, SwishHeaders } from './HybridCryptography';

const server = new HandshakeServer();

describe('HybridCryptography.validateSwishHeader', () => {
  const headers: SwishHeaders = {
    swish_action: '',
    swish_iv: '',
    swish_key: '',
    swish_next: '',
    swish_sess_id: '',
  };

  const body: SwishBody = {
    enc_body: '',
    is_json: false,
  };

  test('should ensure there is a sessionId value to associate the session with', () => {
    try {
      server.handleHandshakeRequest(headers);
    } catch (err) {
      expect((err as Error).message).toMatch('SESSION_ID_INVALID');
    }
  });

  test('should ensure the swish_action value is handshake_init', () => {
    try {
      headers.swish_sess_id = 'adonisv79';
      headers.swish_action = 'something';
      server.handleHandshakeRequest(headers);
    } catch (err) {
      expect((err as Error).message).toMatch('HANDSHAKE_INVALID_INIT');
    }
  });

  test('should ensure the swish_iv is valid', () => {
    try {
      headers.swish_sess_id = 'adonisv79';
      headers.swish_action = 'handshake_init';
      server.handleHandshakeRequest(headers);
    } catch (err) {
      expect((err as Error).message).toMatch('HANDSHAKE_AES_IV_INVALID');
    }
  });
});
