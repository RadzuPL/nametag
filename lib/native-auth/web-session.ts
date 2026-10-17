import { cookies } from 'next/headers';
import { getToken } from 'next-auth/jwt';
import { auth } from '@/lib/auth';
import { env } from '@/lib/env';
import { blacklistToken } from '@/lib/token-blacklist';
import { createModuleLogger } from '@/lib/logger';

const log = createModuleLogger('native-auth');

const SESSION_COOKIE = /^(__Secure-)?authjs\.session-token(\.\d+)?$/;
const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * The user the sign-in sheet just authenticated, if any. Lives here rather
 * than in the route because the route is a provider redirect target (a
 * cross-site GET), so it cannot sit behind withAuth's same-origin check; it
 * only turns the fresh session into a single-use code and ends that session.
 */
export async function getWebSessionUserId(): Promise<string | null> {
  const session = await auth();
  return session?.user?.id ?? null;
}

/**
 * End the web session the sign-in sheet just created: blacklist its JWT (as
 * logout does) and delete the session cookie and any chunks.
 */
export async function endWebSession(request: Request): Promise<void> {
  const store = await cookies();
  const secureCookie = store.getAll().some((c) => c.name.startsWith('__Secure-authjs.session-token'));

  try {
    const token = await getToken({ req: request, secret: env.NEXTAUTH_SECRET, secureCookie });
    if (token?.jti) {
      const expiresAt = new Date(typeof token.exp === 'number' ? token.exp * 1000 : Date.now() + THIRTY_DAYS_MS);
      await blacklistToken(token.jti, expiresAt);
    }
  } catch (error) {
    log.warn({ err: error instanceof Error ? error : new Error(String(error)) }, 'Failed to blacklist handoff web session');
  }

  for (const cookie of store.getAll()) {
    if (SESSION_COOKIE.test(cookie.name)) {
      store.delete(cookie.name);
    }
  }
}
