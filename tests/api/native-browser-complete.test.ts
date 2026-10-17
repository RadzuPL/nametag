import { describe, it, expect, beforeEach, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  store: new Map<string, string>(),
  deleted: [] as string[],
  auth: vi.fn(),
  issue: vi.fn(),
  endWebSession: vi.fn(),
}));

vi.mock('next/headers', () => ({
  cookies: async () => ({
    get: (name: string) => (mocks.store.has(name) ? { name, value: mocks.store.get(name) } : undefined),
    delete: (name: string) => {
      mocks.deleted.push(name);
      mocks.store.delete(name);
    },
  }),
}));
vi.mock('@/lib/native-auth/codes', () => ({ issueNativeAuthCode: mocks.issue }));
vi.mock('@/lib/native-auth/web-session', () => ({
  endWebSession: mocks.endWebSession,
  getWebSessionUserId: async () => {
    const session: { user?: { id?: string } } | null = await mocks.auth();
    return session?.user?.id ?? null;
  },
}));
vi.mock('@/lib/prisma', () => ({ prisma: {} }));
vi.mock('@/lib/env', () => ({ env: { NEXTAUTH_SECRET: 's'.repeat(32), NEXTAUTH_URL: 'https://nametag.example' } }));
vi.mock('@/lib/logger', () => {
  const log = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
  return { logger: log, createModuleLogger: vi.fn(() => log) };
});

import { GET } from '@/app/api/auth/native/browser/complete/route';
import { signPending, PENDING_COOKIE, REASON_COOKIE } from '@/lib/native-auth/browser-cookie';

const STATE = 'abcdefghijklmnop';
const device = { name: 'Pixel', platform: 'ANDROID' as const, appVersion: '1.0.0' };
const pendingValue = (state = STATE) =>
  signPending({ provider: 'oidc', state, codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', device, exp: Date.now() + 60_000 });

const complete = () => GET(new Request('https://nametag.example/api/auth/native/browser/complete'));

describe('GET /api/auth/native/browser/complete', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.store.clear();
    mocks.deleted = [];
    mocks.issue.mockResolvedValue('ntc_code');
  });

  it('shows the expired page without a valid pending cookie', async () => {
    mocks.store.set(PENDING_COOKIE, 'garbage');
    const res = await complete();
    expect(res.headers.get('location')).toBe('https://nametag.example/native-auth/expired');
    expect(mocks.issue).not.toHaveBeenCalled();
  });

  it('hands a code to the app, ends the web session and clears the cookie', async () => {
    mocks.store.set(PENDING_COOKIE, pendingValue());
    mocks.auth.mockResolvedValue({ user: { id: 'u1' } });

    const res = await complete();

    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe(`nametag://auth/callback?code=ntc_code&state=${STATE}`);
    expect(mocks.issue).toHaveBeenCalledWith('u1', expect.objectContaining({ codeChallenge: expect.any(String), device }));
    expect(mocks.endWebSession).toHaveBeenCalled();
    expect(mocks.deleted).toContain(PENDING_COOKIE);
  });

  it('returns the latest state when start ran twice (Review Focus 4)', async () => {
    mocks.store.set(PENDING_COOKIE, pendingValue('secondstate12345'));
    mocks.auth.mockResolvedValue({ user: { id: 'u1' } });
    const res = await complete();
    expect(new URL(res.headers.get('location') ?? '').searchParams.get('state')).toBe('secondstate12345');
  });

  it.each([
    [undefined, 'sign_in_failed'],
    ['email_not_verified', 'email_not_verified'],
    ['account_linked_elsewhere', 'account_linked_elsewhere'],
    ['made_up', 'sign_in_failed'],
  ])('without a session, reports reason cookie %s as %s and clears both cookies', async (reason, expected) => {
    mocks.store.set(PENDING_COOKIE, pendingValue());
    if (reason) mocks.store.set(REASON_COOKIE, reason);
    mocks.auth.mockResolvedValue(null);

    const res = await complete();

    expect(res.headers.get('location')).toBe(`nametag://auth/callback?error=${expected}&state=${STATE}`);
    expect(mocks.issue).not.toHaveBeenCalled();
    expect(mocks.deleted).toEqual(expect.arrayContaining([PENDING_COOKIE, REASON_COOKIE]));
  });
});
