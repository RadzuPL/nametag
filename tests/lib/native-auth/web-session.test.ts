import { describe, it, expect, beforeEach, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  getToken: vi.fn(),
  blacklistToken: vi.fn(),
  deleted: [] as string[],
  names: [] as string[],
  auth: vi.fn(),
}));

vi.mock('next/headers', () => ({
  cookies: async () => ({
    getAll: () => mocks.names.map((name) => ({ name, value: 'v' })),
    delete: (name: string) => {
      mocks.deleted.push(name);
    },
  }),
}));
vi.mock('next-auth/jwt', () => ({ getToken: mocks.getToken }));
vi.mock('@/lib/token-blacklist', () => ({ blacklistToken: mocks.blacklistToken }));
vi.mock('@/lib/auth', () => ({ auth: mocks.auth }));
vi.mock('@/lib/env', () => ({ env: { NEXTAUTH_SECRET: 's'.repeat(32) } }));
vi.mock('@/lib/logger', () => {
  const log = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
  return { logger: log, createModuleLogger: vi.fn(() => log) };
});

import { endWebSession, getWebSessionUserId } from '@/lib/native-auth/web-session';

describe('endWebSession', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.deleted = [];
    mocks.names = ['authjs.session-token', 'authjs.session-token.0', 'other'];
  });

  it('blacklists the JWT and deletes exactly the session cookies', async () => {
    mocks.getToken.mockResolvedValue({ jti: 'j1', exp: 2000000000 });
    await endWebSession(new Request('https://nametag.example/x'));
    expect(mocks.blacklistToken).toHaveBeenCalledWith('j1', new Date(2000000000 * 1000));
    expect(mocks.deleted).toEqual(['authjs.session-token', 'authjs.session-token.0']);
  });

  it('still deletes the cookies when blacklisting fails', async () => {
    mocks.getToken.mockResolvedValue({ jti: 'j1', exp: 2000000000 });
    mocks.blacklistToken.mockRejectedValue(new Error('redis down'));
    await endWebSession(new Request('https://nametag.example/x'));
    expect(mocks.deleted).toHaveLength(2);
  });

  it('uses the secure cookie name when the secure cookie is present', async () => {
    mocks.names = ['__Secure-authjs.session-token'];
    mocks.getToken.mockResolvedValue(null);
    await endWebSession(new Request('https://nametag.example/x'));
    expect(mocks.getToken).toHaveBeenCalledWith(expect.objectContaining({ secureCookie: true }));
    expect(mocks.blacklistToken).not.toHaveBeenCalled();
    expect(mocks.deleted).toEqual(['__Secure-authjs.session-token']);
  });
});

describe('getWebSessionUserId', () => {
  it('returns the signed-in user id, or null without a session', async () => {
    mocks.auth.mockResolvedValueOnce({ user: { id: 'u1' } });
    expect(await getWebSessionUserId()).toBe('u1');
    mocks.auth.mockResolvedValueOnce(null);
    expect(await getWebSessionUserId()).toBeNull();
  });
});
