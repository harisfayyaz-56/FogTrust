/**
 * Frontend runtime configuration.
 *
 * Real mode is the default: VITE_USE_MOCK=false (or unset) talks to the Django
 * broker through the Vite proxy. Set VITE_USE_MOCK=true to start offline with
 * the bundled demo fixtures. The demo toggle in the navbar can still switch
 * modes at runtime, but a real-mode failure never silently falls back to mock.
 */

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined || value.trim() === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(value.trim().toLowerCase());
}

export const USE_MOCK_DEFAULT = parseBoolean(import.meta.env.VITE_USE_MOCK, false);

/** Empty means "same origin", so the Vite dev proxy handles /api. */
export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').trim().replace(/\/+$/, '');

/** Dispatched by the API client when the server rejects a session (401). */
export const SESSION_EXPIRED_EVENT = 'fogtrust:session-expired';

/** Dispatched after any successful API response, which resets the idle timer. */
export const SESSION_ACTIVITY_EVENT = 'fogtrust:session-activity';

export function apiUrl(path: string): string {
  if (!API_BASE_URL) return path;
  return `${API_BASE_URL}${path.startsWith('/') ? path : `/${path}`}`;
}
