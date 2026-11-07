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

export async function fetchCsrfToken(): Promise<string> {
  const cookieVal = getCookie('csrftoken');
  if (cookieVal) {
    cachedCsrfToken = cookieVal;
    return cookieVal;
  }
  try {
    const res = await fetch('/api/v1/auth/csrf/', {
      method: 'GET',
      credentials: 'include',
    });
    if (res.ok) {
      const data = await res.json();
      if (data && data.csrf_token) {
        cachedCsrfToken = data.csrf_token;
        return data.csrf_token;
      }
    }
  } catch (err) {
    console.warn('Could not fetch CSRF token from server:', err);
  }
  return cachedCsrfToken || '';
}

async function request<T>(
  path: string,
  options: RequestInit = {},
  useDemoFallback = false,
  fallbackData?: T
): Promise<T> {
  const method = (options.method || 'GET').toUpperCase();
  const headers = new Headers(options.headers || {});

  if (!headers.has('Content-Type') && method !== 'GET' && options.body) {
    headers.set('Content-Type', 'application/json');
  }

  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    const csrf = cachedCsrfToken || getCookie('csrftoken') || (await fetchCsrfToken());
    if (csrf) {
      headers.set('X-CSRFToken', csrf);
    }
  }

  try {
    const response = await fetch(path, {
      ...options,
      headers,
      credentials: 'include',
    });

    // Check for rotated CSRF cookie
    const freshCookie = getCookie('csrftoken');
    if (freshCookie) {
      cachedCsrfToken = freshCookie;
    }

    if (response.status === 204) {
      return null as unknown as T;
    }

    const data = await response.json().catch(() => null);

    if (!response.ok) {
      if (data && data.error) {
        throw new ApiError(
          data.error.code || 'REQUEST_FAILED',
          data.error.message || 'Request failed',
          response.status,
          data.error.request_id,
          data.error.details
        );
      }
      throw new ApiError('REQUEST_FAILED', `HTTP ${response.status}`, response.status);
    }

    return data as T;
  } catch (err: unknown) {
    if (useDemoFallback && fallbackData !== undefined) {
      console.warn(`Falling back to demo data for ${path}:`, err);
      return fallbackData;
    }
    throw err;
  }
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
  return request<TrustScoreRecord[]>(
    `/api/v1/nodes/${nodeId}/trust/`,
    {},
    isDemo,
    MOCK_TRUST_HISTORY[nodeId] || []
  );
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
  return request<PaginatedResponse<EnrollmentToken>>(`/api/v1/enrollment-tokens/${query}`, {}, isDemo, fallback);
}

export async function createEnrollmentToken(label: string, expiresInMinutes: number = 15): Promise<EnrollmentToken> {
  return request<EnrollmentToken>('/api/v1/enrollment-tokens/', {
    method: 'POST',
    body: JSON.stringify({ label, expires_in_minutes: expiresInMinutes }),
  });
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

  return request<PaginatedResponse<Task>>(`/api/v1/tasks/list/?${query.toString()}`, {}, isDemo, fallback);
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
  return request<PolicyConfig>('/api/v1/policy/', {}, isDemo, MOCK_POLICY);
}

export async function updatePolicy(values: Record<string, unknown>, changeReason: string): Promise<PolicyConfig> {
  return request<PolicyConfig>('/api/v1/policy/', {
    method: 'POST',
    body: JSON.stringify({ values, change_reason: changeReason }),
  });
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

