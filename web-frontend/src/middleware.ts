// web-frontend/src/middleware.ts
import { defineMiddleware } from 'astro:middleware';

const PUBLIC_PATHS = ['/login', '/api/login'];

export const onRequest = defineMiddleware(async (context, next) => {
  const { pathname } = context.url;

  if (PUBLIC_PATHS.some(p => pathname.startsWith(p))) {
    return next();
  }

  const session = context.cookies.get('soc_session');
  if (!session?.value) {
    return context.redirect(`/login?next=${encodeURIComponent(pathname)}`);
  }

  return next();
});