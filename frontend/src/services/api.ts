import {
  AuthMeResponse,
  HealthResponse,
  NodeItem,
  EnrollmentToken,
  Decision,
  AuditEvent,
  AuditVerifyReport,
  Task,
  PolicyConfig,
  User,
  PaginatedResponse,
  TrustScoreRecord,
  HeartbeatRecord,
} from '../types/api';
import { apiUrl, SESSION_EXPIRED_EVENT, SESSION_ACTIVITY_EVENT } from '../config/env';
import {
  MOCK_HEALTH,
  MOCK_NODES,
  MOCK_ENROLLMENT_TOKENS,
  MOCK_DECISIONS,
  MOCK_AUDIT_EVENTS,
  MOCK_TASKS,
  MOCK_POLICY,
  MOCK_USERS,
  MOCK_TRUST_HISTORY,
  MOCK_HEARTBEATS,
} from './mockData';

export class ApiError extends Error {
  code: string;
  status: number;
  requestId?: string;
  details?: Record<string, unknown>;

  constructor(code: string, message: string, status: number, requestId?: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    this.requestId = requestId;
    this.details = details;
  }
}

function getCookie(name: string): string | null {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) {
    return parts.pop()?.split(';').shift() || null;
  }
  return null;
}

let cachedCsrfToken: string | null = null;

function readCsrfCookie(): string | null {
  const cookieVal = getCookie('csrftoken');
  if (cookieVal) cachedCsrfToken = cookieVal;
  return cookieVal;
}

export async function fetchCsrfToken(force = false): Promise<string> {
  if (!force) {
    const cookieVal = readCsrfCookie();
    if (cookieVal) return cookieVal;
  }

  try {
    const res = await fetch(apiUrl('/api/v1/auth/csrf/'), {
      method: 'GET',
      credentials: 'include',
      cache: 'no-store',
    });
    if (res.ok) {
      const data = await res.json().catch(() => null);
      const token =
        (data && typeof data.csrf_token === 'string' && data.csrf_token) || readCsrfCookie();
      if (token) {
        cachedCsrfToken = token;
        return token;
      }
    }
  } catch (err) {
    console.warn('Could not fetch CSRF token from server:', err);
  }
  return cachedCsrfToken || '';
}

const STATUS_CODES: Record<number, string> = {
  400: 'VALIDATION_ERROR',
  401: 'AUTH_REQUIRED',
  403: 'PERMISSION_DENIED',
  404: 'NOT_FOUND',
  405: 'METHOD_NOT_ALLOWED',
  406: 'NOT_ACCEPTABLE',
  409: 'CONFLICT',
  413: 'PAYLOAD_TOO_LARGE',
  415: 'UNSUPPORTED_MEDIA_TYPE',
  422: 'RESULT_INTEGRITY_FAILED',
  429: 'RATE_LIMITED',
  500: 'INTERNAL_ERROR',
  502: 'SERVICE_UNAVAILABLE',
  503: 'SERVICE_UNAVAILABLE',
  504: 'SERVICE_UNAVAILABLE',
};

/**
 * Turn a server or transport failure into a short, safe message. The backend
 * never sends secrets or stack traces, and neither do we: unknown responses
 * fall back to a generic sentence.
 */
function friendlyMessage(status: number, code: string, serverMessage?: string): string {
  if (status === 401) {
    if (code === 'AUTH_INVALID_CREDENTIALS' || code === 'AUTH_ACCOUNT_DISABLED') {
      return 'Invalid username or password.';
    }
    if (code === 'AUTH_SESSION_EXPIRED' || code === 'AUTH_REQUIRED') {
      return 'Your session has expired. Please sign in again.';
    }
    return 'You need to sign in to continue.';
  }
  if (status === 403) {
    if (code === 'CSRF_FAILED') {
      return 'Your security token expired. Refresh the page and try again.';
    }
    if (code === 'PERMISSION_DENIED') {
      return 'Your role is not allowed to perform this action.';
    }
    return serverMessage || 'You are not allowed to perform this action.';
  }
  if (status === 413) return 'The request is too large. Reduce the payload and try again.';
  if (status === 404) return 'The requested resource is not available on the FogTrust broker.';
  if (status === 422) return 'The result failed an integrity check, so it was not accepted.';
  if (status === 429) return 'Too many requests. Please wait a moment and try again.';
  if (status === 500) {
    return 'The broker hit an internal error. Try again; if it persists, contact an administrator.';
  }
  if (status === 502 || status === 503 || status === 504) {
    return 'The FogTrust broker is unavailable. Check that the backend is running.';
  }
  return serverMessage || 'The request could not be completed.';
}

function notifySessionExpired(): void {
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new Event(SESSION_EXPIRED_EVENT));
  }
}

function notifyActivity(): void {
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new Event(SESSION_ACTIVITY_EVENT));
  }
}

async function performRequest<T>(
  path: string,
  options: RequestInit,
  allowCsrfRetry: boolean
): Promise<T> {
  const method = (options.method || 'GET').toUpperCase();
  const headers = new Headers(options.headers || {});

  if (!headers.has('Content-Type') && method !== 'GET' && options.body) {
    headers.set('Content-Type', 'application/json');
  }

  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    const csrf = cachedCsrfToken || readCsrfCookie() || (await fetchCsrfToken());
    if (csrf) {
      headers.set('X-CSRFToken', csrf);
    }
  }

  let response: Response;
  try {
    response = await fetch(apiUrl(path), {
      ...options,
      headers,
      credentials: 'include',
    });
  } catch {
    throw new ApiError(
      'NETWORK_ERROR',
      'Cannot reach the FogTrust broker. Check that the backend is running and the API URL is correct.',
      0
    );
  }

  // Login rotates the CSRF token, so remember the new cookie immediately.
  readCsrfCookie();

  // A successful request proves the session is alive and resets the server's
  // idle timer, so the dashboard countdown must reset too.
  if (response.ok) notifyActivity();

  if (response.status === 204) {
    return null as unknown as T;
  }

  const data = await response.json().catch(() => null);

  if (!response.ok) {
    const code = data?.error?.code || STATUS_CODES[response.status] || 'REQUEST_FAILED';
    const serverMessage = data?.error?.message;

    // A stale CSRF cookie is recoverable: fetch a fresh token and retry once.
    if (response.status === 403 && code === 'CSRF_FAILED' && allowCsrfRetry) {
      await fetchCsrfToken(true);
      return performRequest<T>(path, options, false);
    }

    if (
      response.status === 401 &&
      code !== 'AUTH_INVALID_CREDENTIALS' &&
      !path.includes('/auth/login/')
    ) {
      notifySessionExpired();
    }

    throw new ApiError(
      code,
      friendlyMessage(response.status, code, serverMessage),
      response.status,
      data?.error?.request_id,
      data?.error?.details
    );
  }

  return data as T;
}

async function request<T>(
  path: string,
  options: RequestInit = {},
  useDemoFallback = false,
  fallbackData?: T
): Promise<T> {
  // Demo mode is offline by definition. Return the fixtures immediately so a
  // running broker with a live session can never leak real data into the demo,
  // and so demo mode makes no network requests at all.
  if (useDemoFallback && fallbackData !== undefined) {
    return fallbackData;
  }

  // Real mode always surfaces errors so a broken backend is never disguised.
  return performRequest<T>(path, options, true);
}

// ---------------------------------------------------------------------------
// Response normalisation
// ---------------------------------------------------------------------------
function asList<T>(value: PaginatedResponse<T> | T[] | null | undefined): T[] {
  if (Array.isArray(value)) return value;
  return value?.results ?? [];
}

function normalizeTrustRecord(record: TrustScoreRecord): TrustScoreRecord {
  const rules = Array.isArray(record.rules_fired) ? record.rules_fired : [];
  const explanation =
    record.explanation ||
    rules
      .map((rule) => rule.reason)
      .filter((reason): reason is string => typeof reason === 'string' && reason.length > 0)
      .join(' ') ||
    `Score changed from ${record.previous_score} to ${record.score}.`;
  return { ...record, rules_fired: rules, explanation };
}

function normalizePolicy(raw: PolicyConfig & { changed_by_username?: string }): PolicyConfig {
  return {
    ...raw,
    changed_by: raw.changed_by || raw.changed_by_username || 'system',
  };
}

function normalizeTask(task: Task & { assigned_node_name?: string | null }): Task {
  return { ...task, assigned_node: task.assigned_node ?? null };
}

function normalizeToken(raw: EnrollmentToken): EnrollmentToken {
  return {
    ...raw,
    created_at: raw.created_at || new Date().toISOString(),
    used_at: raw.used_at ?? null,
    cancelled_at: raw.cancelled_at ?? null,
  };
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------
export async function getHealth(isDemo = false): Promise<HealthResponse> {
  return request<HealthResponse>('/api/v1/health/', {}, isDemo, MOCK_HEALTH);
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------
export async function login(username: string, password: string): Promise<{ user: { username: string; role: string }; session_expires_in: number }> {
  // Ensure we have a CSRF token before login
  await fetchCsrfToken();
  return request<{ user: { username: string; role: string }; session_expires_in: number }>('/api/v1/auth/login/', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
}

export async function logout(): Promise<void> {
  return request<void>('/api/v1/auth/logout/', {
    method: 'POST',
  });
}

export async function getMe(): Promise<AuthMeResponse> {
  return request<AuthMeResponse>('/api/v1/auth/me/');
}

// ---------------------------------------------------------------------------
// Nodes & Revocation
// ---------------------------------------------------------------------------
export async function getNodes(
  params: { status?: string; min_trust?: number; search?: string; page?: number } = {},
  isDemo = false
): Promise<PaginatedResponse<NodeItem>> {
  const query = new URLSearchParams();
  if (params.status) query.set('status', params.status);
  if (params.min_trust !== undefined) query.set('min_trust', params.min_trust.toString());
  if (params.search) query.set('search', params.search);
  if (params.page) query.set('page', params.page.toString());

  const fallback: PaginatedResponse<NodeItem> = {
    count: MOCK_NODES.length,
    next: null,
    previous: null,
    results: MOCK_NODES.filter((n) => {
      if (params.status && n.status !== params.status) return false;
      if (params.min_trust !== undefined && n.trust_score < params.min_trust) return false;
      if (params.search && !n.name.toLowerCase().includes(params.search.toLowerCase())) return false;
      return true;
    }),
  };

  return request<PaginatedResponse<NodeItem>>(`/api/v1/nodes/?${query.toString()}`, {}, isDemo, fallback);
}

export async function getNodeDetail(id: string, isDemo = false): Promise<NodeItem> {
  const fallback = MOCK_NODES.find((n) => n.id === id) || MOCK_NODES[0];
  return request<NodeItem>(`/api/v1/nodes/${id}/`, {}, isDemo, fallback);
}

export async function revokeNode(id: string, confirmName: string, reason: string): Promise<NodeItem> {
  return request<NodeItem>(`/api/v1/nodes/${id}/revoke/`, {
    method: 'POST',
    body: JSON.stringify({ confirm_name: confirmName, reason }),
  });
}

// ---------------------------------------------------------------------------
// Trust score history (FR-4)
// ---------------------------------------------------------------------------
export async function getNodeTrustHistory(
  nodeId: string,
  isDemo = false
): Promise<TrustScoreRecord[]> {
  // The backend returns a standard paginated envelope; older demo fixtures
  // (and the contract wording) use a bare array. Accept both.
  const response = await request<PaginatedResponse<TrustScoreRecord> | TrustScoreRecord[]>(
    `/api/v1/nodes/${nodeId}/trust/`,
    {},
    isDemo,
    MOCK_TRUST_HISTORY[nodeId] || []
  );
  return asList(response).map(normalizeTrustRecord);
}

// ---------------------------------------------------------------------------
// Heartbeat history, including rejected attempts (FR-2 / Evidence)
// ---------------------------------------------------------------------------
export async function getNodeHeartbeats(
  nodeId: string,
  params: { accepted?: boolean; page?: number } = {},
  isDemo = false
): Promise<PaginatedResponse<HeartbeatRecord>> {
  const query = new URLSearchParams();
  if (params.accepted !== undefined) query.set('accepted', String(params.accepted));
  if (params.page) query.set('page', params.page.toString());

  const fallback: PaginatedResponse<HeartbeatRecord> = {
    count: 0,
    next: null,
    previous: null,
    results: MOCK_HEARTBEATS.filter((heartbeat) => {
      if (heartbeat.node !== nodeId) return false;
      if (params.accepted !== undefined && heartbeat.accepted !== params.accepted) return false;
      return true;
    }).sort((a, b) => b.received_at.localeCompare(a.received_at)),
  };
  fallback.count = fallback.results.length;

  return request<PaginatedResponse<HeartbeatRecord>>(
    `/api/v1/nodes/${nodeId}/heartbeats/?${query.toString()}`,
    {},
    isDemo,
    fallback
  );
}

/**
 * Evidence view helper: rejected heartbeats are stored per node, so demo mode
 * reads the mock set directly and real mode fans out to each node's history.
 * Partial failures are tolerated so one unavailable node does not hide the rest
 * of the evidence.
 */
export async function getAllRejectedHeartbeats(isDemo = false): Promise<HeartbeatRecord[]> {
  if (isDemo) {
    return MOCK_HEARTBEATS.filter((heartbeat) => !heartbeat.accepted).sort((a, b) =>
      b.received_at.localeCompare(a.received_at)
    );
  }

  const nodeList = await getNodes({}, false);
  const settled = await Promise.allSettled(
    nodeList.results.map((node) => getNodeHeartbeats(node.id, { accepted: false }, false))
  );

  const rejected: HeartbeatRecord[] = [];
  for (const entry of settled) {
    if (entry.status === 'fulfilled') {
      rejected.push(...entry.value.results);
    }
  }

  return rejected.sort((a, b) => b.received_at.localeCompare(a.received_at));
}

// ---------------------------------------------------------------------------
// Enrollment Tokens
// ---------------------------------------------------------------------------
export async function getEnrollmentTokens(
  status?: string,
  isDemo = false
): Promise<PaginatedResponse<EnrollmentToken>> {
  const query = status ? `?status=${status}` : '';
  const fallback: PaginatedResponse<EnrollmentToken> = {
    count: MOCK_ENROLLMENT_TOKENS.length,
    next: null,
    previous: null,
    results: MOCK_ENROLLMENT_TOKENS.filter((t) => {
      if (!status) return true;
      if (status === 'pending') return !t.used_at && !t.cancelled_at;
      if (status === 'used') return !!t.used_at;
      if (status === 'cancelled') return !!t.cancelled_at;
      return true;
    }),
  };
  const response = await request<PaginatedResponse<EnrollmentToken>>(
    `/api/v1/enrollment-tokens/${query}`,
    {},
    isDemo,
    fallback
  );
  return { ...response, results: (response.results || []).map(normalizeToken) };
}

export async function createEnrollmentToken(label: string, expiresInMinutes: number = 15): Promise<EnrollmentToken> {
  // The creation response intentionally contains only id/label/token/expires_at;
  // fill the list-only fields so the UI never sees undefined.
  const created = await request<EnrollmentToken>('/api/v1/enrollment-tokens/', {
    method: 'POST',
    body: JSON.stringify({ label, expires_in_minutes: expiresInMinutes }),
  });
  return normalizeToken(created);
}

export async function cancelEnrollmentToken(id: string): Promise<void> {
  return request<void>(`/api/v1/enrollment-tokens/${id}/cancel/`, {
    method: 'POST',
  });
}

// ---------------------------------------------------------------------------
// Decisions (Evidence View - FR-7)
// ---------------------------------------------------------------------------
export async function getDecisions(
  params: { subject_type?: string; decision?: string; reason_code?: string; since?: string; page?: number } = {},
  isDemo = false
): Promise<PaginatedResponse<Decision>> {
  const query = new URLSearchParams();
  if (params.subject_type) query.set('subject_type', params.subject_type);
  if (params.decision) query.set('decision', params.decision);
  if (params.reason_code) query.set('reason_code', params.reason_code);
  if (params.since) query.set('since', params.since);
  if (params.page) query.set('page', params.page.toString());

  const fallback: PaginatedResponse<Decision> = {
    count: MOCK_DECISIONS.length,
    next: null,
    previous: null,
    results: MOCK_DECISIONS.filter((d) => {
      if (params.subject_type && d.subject_type !== params.subject_type) return false;
      if (params.decision && d.decision !== params.decision) return false;
      if (params.reason_code && d.reason_code !== params.reason_code) return false;
      return true;
    }),
  };

  return request<PaginatedResponse<Decision>>(`/api/v1/decisions/?${query.toString()}`, {}, isDemo, fallback);
}

// ---------------------------------------------------------------------------
// Audit Log & Verification
// ---------------------------------------------------------------------------
export async function getAuditEvents(
  params: { action?: string; actor?: string; outcome?: string; reason_code?: string; since?: string; until?: string; page?: number } = {},
  isDemo = false
): Promise<PaginatedResponse<AuditEvent>> {
  const query = new URLSearchParams();
  if (params.action) query.set('action', params.action);
  if (params.actor) query.set('actor', params.actor);
  if (params.outcome) query.set('outcome', params.outcome);
  if (params.reason_code) query.set('reason_code', params.reason_code);
  if (params.since) query.set('since', params.since);
  if (params.until) query.set('until', params.until);
  if (params.page) query.set('page', params.page.toString());

  const fallback: PaginatedResponse<AuditEvent> = {
    count: MOCK_AUDIT_EVENTS.length,
    next: null,
    previous: null,
    results: MOCK_AUDIT_EVENTS.filter((e) => {
      if (params.action && e.action !== params.action) return false;
      if (params.outcome && e.outcome !== params.outcome) return false;
      if (params.reason_code && e.reason_code !== params.reason_code) return false;
      return true;
    }),
  };

  return request<PaginatedResponse<AuditEvent>>(`/api/v1/audit/?${query.toString()}`, {}, isDemo, fallback);
}

export async function verifyAuditChain(isDemo = false): Promise<AuditVerifyReport> {
  const fallback: AuditVerifyReport = {
    valid: true,
    events_checked: MOCK_AUDIT_EVENTS.length,
    first_broken_sequence: null,
    problem: null,
    checked_at: new Date().toISOString(),
  };

  return request<AuditVerifyReport>('/api/v1/audit/verify/', { method: 'POST' }, isDemo, fallback);
}

// ---------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------
export async function getTasks(
  params: { status?: string; node?: string; page?: number } = {},
  isDemo = false
): Promise<PaginatedResponse<Task>> {
  const query = new URLSearchParams();
  if (params.status) query.set('status', params.status);
  if (params.node) query.set('node', params.node);
  if (params.page) query.set('page', params.page.toString());

  const fallback: PaginatedResponse<Task> = {
    count: MOCK_TASKS.length,
    next: null,
    previous: null,
    results: MOCK_TASKS.filter((t) => {
      if (params.status && t.status !== params.status) return false;
      if (params.node && t.assigned_node !== params.node) return false;
      return true;
    }),
  };

  const response = await request<PaginatedResponse<Task>>(
    `/api/v1/tasks/list/?${query.toString()}`,
    {},
    isDemo,
    fallback
  );
  return { ...response, results: (response.results || []).map(normalizeTask) };
}

export async function submitTask(taskData: {
  task_type: string;
  payload: Record<string, unknown>;
  priority: number;
  idempotency_key: string;
}): Promise<Task> {
  return request<Task>('/api/v1/tasks/', {
    method: 'POST',
    headers: {
      'Idempotency-Key': taskData.idempotency_key,
    },
    body: JSON.stringify({
      task_type: taskData.task_type,
      payload: taskData.payload,
      priority: taskData.priority,
    }),
  });
}

export async function cancelTask(taskId: string): Promise<void> {
  return request<void>(`/api/v1/tasks/${taskId}/cancel/`, {
    method: 'POST',
  });
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------
export async function getPolicy(isDemo = false): Promise<PolicyConfig> {
  const policy = await request<PolicyConfig & { changed_by_username?: string }>(
    '/api/v1/policy/',
    {},
    isDemo,
    MOCK_POLICY
  );
  return normalizePolicy(policy);
}

export async function updatePolicy(values: Record<string, unknown>, changeReason: string): Promise<PolicyConfig> {
  const policy = await request<PolicyConfig & { changed_by_username?: string }>('/api/v1/policy/', {
    method: 'POST',
    body: JSON.stringify({ values, change_reason: changeReason }),
  });
  return normalizePolicy(policy);
}

// ---------------------------------------------------------------------------
// Users (Admin only)
// ---------------------------------------------------------------------------
export async function getUsers(role?: string, isDemo = false): Promise<PaginatedResponse<User>> {
  const query = role ? `?role=${role}` : '';
  const fallback: PaginatedResponse<User> = {
    count: MOCK_USERS.length,
    next: null,
    previous: null,
    results: MOCK_USERS.filter((u) => (!role ? true : u.role === role)),
  };
  return request<PaginatedResponse<User>>(`/api/v1/users/${query}`, {}, isDemo, fallback);
}

export async function createUser(userData: { username: string; role: string; password?: string }): Promise<User> {
  return request<User>('/api/v1/users/', {
    method: 'POST',
    body: JSON.stringify(userData),
  });
}

export async function updateUser(userId: string | number, updates: { role?: string; is_active?: boolean }): Promise<User> {
  return request<User>(`/api/v1/users/${userId}/`, {
    method: 'PATCH',
    body: JSON.stringify(updates),
  });
}

// Sanitized report generation lives in services/report.ts so it can be unit
// tested without a browser or network dependency.

