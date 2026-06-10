// web-frontend/src/pages/api/users/[id].ts
export const prerender = false;
import type { APIRoute } from 'astro';

const AUTH_URL = process.env.AUTH_SERVICE_URL ?? 'http://localhost:4000';

export const DELETE: APIRoute = async ({ request, params }) => {
  const cookie = request.headers.get('cookie') ?? '';
  const res = await fetch(`${AUTH_URL}/users/${params.id}`, {
    method: 'DELETE',
    headers: { 'Cookie': cookie },
  });
  const data = await res.json();
  return new Response(JSON.stringify(data), {
    status: res.status,
    headers: { 'Content-Type': 'application/json' },
  });
};