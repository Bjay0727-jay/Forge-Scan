import { describe, it, expect } from 'vitest';
import {
  generateSalt,
  hashPassword,
  verifyPassword,
  signJWT,
  verifyJWT,
  hashApiKey,
  generateApiKey,
} from './crypto';

const HEX_REGEX = /^[0-9a-f]+$/;

// --- generateSalt ---

describe('generateSalt', () => {
  it('returns a 32-character hex string (16 bytes)', () => {
    const salt = generateSalt();
    expect(salt).toHaveLength(32);
    expect(salt).toMatch(HEX_REGEX);
  });

  it('returns different values on successive calls', () => {
    const salt1 = generateSalt();
    const salt2 = generateSalt();
    expect(salt1).not.toBe(salt2);
  });
});

// --- hashPassword ---

describe('hashPassword', () => {
  it('returns a 64-character hex string (32 bytes)', async () => {
    const hash = await hashPassword('password', generateSalt());
    expect(hash).toHaveLength(64);
    expect(hash).toMatch(HEX_REGEX);
  });

  it('is deterministic — same input produces same hash', async () => {
    const salt = generateSalt();
    const hash1 = await hashPassword('password', salt);
    const hash2 = await hashPassword('password', salt);
    expect(hash1).toBe(hash2);
  });

  it('different passwords produce different hashes', async () => {
    const salt = generateSalt();
    const hash1 = await hashPassword('password1', salt);
    const hash2 = await hashPassword('password2', salt);
    expect(hash1).not.toBe(hash2);
  });

  it('different salts produce different hashes for same password', async () => {
    const hash1 = await hashPassword('password', generateSalt());
    const hash2 = await hashPassword('password', generateSalt());
    expect(hash1).not.toBe(hash2);
  });

  it('handles empty password string', async () => {
    const hash = await hashPassword('', generateSalt());
    expect(hash).toHaveLength(64);
    expect(hash).toMatch(HEX_REGEX);
  });

  it('handles unicode passwords', async () => {
    const hash = await hashPassword('пароль🔑', generateSalt());
    expect(hash).toHaveLength(64);
    expect(hash).toMatch(HEX_REGEX);
  });
});

// --- verifyPassword ---

describe('verifyPassword', () => {
  it('returns true for matching password/salt/hash triple', async () => {
    const salt = generateSalt();
    const hash = await hashPassword('myPassword', salt);
    expect(await verifyPassword('myPassword', salt, hash)).toBe(true);
  });

  it('returns false for wrong password', async () => {
    const salt = generateSalt();
    const hash = await hashPassword('correctPassword', salt);
    expect(await verifyPassword('wrongPassword', salt, hash)).toBe(false);
  });

  it('returns false for wrong salt', async () => {
    const salt = generateSalt();
    const hash = await hashPassword('password', salt);
    expect(await verifyPassword('password', generateSalt(), hash)).toBe(false);
  });

  it('returns false for tampered hash (single char changed)', async () => {
    const salt = generateSalt();
    const hash = await hashPassword('password', salt);
    // Flip one character
    const tampered = hash[0] === 'a' ? 'b' + hash.slice(1) : 'a' + hash.slice(1);
    expect(await verifyPassword('password', salt, tampered)).toBe(false);
  });
});

// --- signJWT ---

describe('signJWT', () => {
  const testPayload = {
    sub: 'user-123',
    email: 'test@example.com',
    role: 'platform_admin',
    display_name: 'Test User',
  };
  const secret = 'test-jwt-secret-key';

  it('returns an object with token, jti, and expiresAt', async () => {
    const result = await signJWT(testPayload, secret);
    expect(result).toHaveProperty('token');
    expect(result).toHaveProperty('jti');
    expect(result).toHaveProperty('expiresAt');
  });

  it('token has three dot-separated base64url parts', async () => {
    const { token } = await signJWT(testPayload, secret);
    const parts = token.split('.');
    expect(parts).toHaveLength(3);
    // Each part should be non-empty base64url
    parts.forEach((part) => {
      expect(part.length).toBeGreaterThan(0);
      expect(part).toMatch(/^[A-Za-z0-9_-]+$/);
    });
  });

  it('jti is a valid UUID format', async () => {
    const { jti } = await signJWT(testPayload, secret);
    expect(jti).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
    );
  });

  it('expiresAt is a valid ISO 8601 string', async () => {
    const { expiresAt } = await signJWT(testPayload, secret);
    const parsed = new Date(expiresAt);
    expect(parsed.getTime()).not.toBeNaN();
  });

  it('default expiry is approximately 24 hours from now', async () => {
    const { expiresAt } = await signJWT(testPayload, secret);
    const expiresMs = new Date(expiresAt).getTime();
    const expectedMs = Date.now() + 86400 * 1000;
    // Allow 5 seconds tolerance
    expect(Math.abs(expiresMs - expectedMs)).toBeLessThan(5000);
  });

  it('custom expiry is respected', async () => {
    const { expiresAt } = await signJWT(testPayload, secret, 3600); // 1 hour
    const expiresMs = new Date(expiresAt).getTime();
    const expectedMs = Date.now() + 3600 * 1000;
    expect(Math.abs(expiresMs - expectedMs)).toBeLessThan(5000);
  });
});

// --- verifyJWT ---

describe('verifyJWT', () => {
  const testPayload = {
    sub: 'user-123',
    email: 'test@example.com',
    role: 'platform_admin',
    display_name: 'Test User',
  };
  const secret = 'test-jwt-secret-key';

  it('successfully verifies a freshly signed token', async () => {
    const { token } = await signJWT(testPayload, secret);
    const payload = await verifyJWT(token, secret);
    expect(payload).not.toBeNull();
    expect(payload!.sub).toBe('user-123');
    expect(payload!.email).toBe('test@example.com');
    expect(payload!.role).toBe('platform_admin');
    expect(payload!.display_name).toBe('Test User');
  });

  it('returns the full payload with iat, exp, jti fields', async () => {
    const { token } = await signJWT(testPayload, secret);
    const payload = await verifyJWT(token, secret);
    expect(payload).toHaveProperty('iat');
    expect(payload).toHaveProperty('exp');
    expect(payload).toHaveProperty('jti');
    expect(typeof payload!.iat).toBe('number');
    expect(typeof payload!.exp).toBe('number');
  });

  it('returns null for expired token', async () => {
    const { token } = await signJWT(testPayload, secret, -1); // expired immediately
    const payload = await verifyJWT(token, secret);
    expect(payload).toBeNull();
  });

  it('returns null for wrong secret', async () => {
    const { token } = await signJWT(testPayload, secret);
    const payload = await verifyJWT(token, 'wrong-secret');
    expect(payload).toBeNull();
  });

  it('returns null for tampered payload', async () => {
    const { token } = await signJWT(testPayload, secret);
    const parts = token.split('.');
    // Tamper with payload by changing a character
    const tamperedPayload =
      parts[1][0] === 'a' ? 'b' + parts[1].slice(1) : 'a' + parts[1].slice(1);
    const tampered = `${parts[0]}.${tamperedPayload}.${parts[2]}`;
    const payload = await verifyJWT(tampered, secret);
    expect(payload).toBeNull();
  });

  it('returns null for malformed token (not 3 parts)', async () => {
    expect(await verifyJWT('only-one-part', secret)).toBeNull();
    expect(await verifyJWT('two.parts', secret)).toBeNull();
    expect(await verifyJWT('', secret)).toBeNull();
  });
});

// --- hashApiKey ---

describe('hashApiKey', () => {
  it('returns a 64-character hex string (SHA-256)', async () => {
    const hash = await hashApiKey('fsk_test_key_12345');
    expect(hash).toHaveLength(64);
    expect(hash).toMatch(HEX_REGEX);
  });

  it('same key produces same hash', async () => {
    const hash1 = await hashApiKey('fsk_test');
    const hash2 = await hashApiKey('fsk_test');
    expect(hash1).toBe(hash2);
  });

  it('different keys produce different hashes', async () => {
    const hash1 = await hashApiKey('fsk_key_a');
    const hash2 = await hashApiKey('fsk_key_b');
    expect(hash1).not.toBe(hash2);
  });
});

// --- generateApiKey ---

describe('generateApiKey', () => {
  it('starts with "fsk_" prefix', () => {
    const key = generateApiKey();
    expect(key.startsWith('fsk_')).toBe(true);
  });

  it('is 68 characters long (4 prefix + 64 hex)', () => {
    const key = generateApiKey();
    expect(key).toHaveLength(68);
  });

  it('returns different values on successive calls', () => {
    const key1 = generateApiKey();
    const key2 = generateApiKey();
    expect(key1).not.toBe(key2);
  });

  it('contains only valid hex characters after prefix', () => {
    const key = generateApiKey();
    const hexPart = key.slice(4);
    expect(hexPart).toMatch(HEX_REGEX);
  });
});
