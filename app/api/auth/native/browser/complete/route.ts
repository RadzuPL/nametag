import { cookies } from 'next/headers';
import { withLogging } from '@/lib/api-utils';
import { createModuleLogger } from '@/lib/logger';
import { issueNativeAuthCode } from '@/lib/native-auth/codes';
import { endWebSession, getWebSessionUserId } from '@/lib/native-auth/web-session';
import {
  EXPIRED_PATH,
  PENDING_COOKIE,
  REASON_COOKIE,
  appRedirect,
  parseReason,
  verifyPending,
} from '@/lib/native-auth/browser-cookie';

export const runtime = 'nodejs';

const log = createModuleLogger('native-auth');

/**
 * Where NextAuth returns after the provider sign-in (and where /login forwards
 * on a provider error). Turns the fresh web session into a single-use code.
 */
export const GET = withLogging(async function GET(request: Request) {
  const store = await cookies();
  const pending = verifyPending(store.get(PENDING_COOKIE)?.value);
  const reason = parseReason(store.get(REASON_COOKIE)?.value);
  store.delete(PENDING_COOKIE);
  store.delete(REASON_COOKIE);

  if (!pending) {
    return Response.redirect(new URL(EXPIRED_PATH, request.url), 302);
  }

  const userId = await getWebSessionUserId();
  if (!userId) {
    const error = reason ?? 'sign_in_failed';
    log.info({ event: 'auth.native.browser.failed', provider: pending.provider, reason: error }, 'Native SSO failed');
    return appRedirect({ error, state: pending.state });
  }

  const code = await issueNativeAuthCode(userId, pending);
  await endWebSession(request);

  log.info(
    { event: 'auth.native.browser.completed', provider: pending.provider, userId },
    'Native SSO completed'
  );
  return appRedirect({ code, state: pending.state });
});
