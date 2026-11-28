import { NodeDisplayStatus, NodeItem } from '../types/api';

/**
 * The API stores only `active` and `revoked`. For operators, a node that has
 * enrolled but never sent a heartbeat is meaningfully different from an active
 * node, so the dashboard derives an "enrolled" state from `last_seen_at`.
 */
export function getNodeDisplayStatus(node: Pick<NodeItem, 'status' | 'last_seen_at'>): NodeDisplayStatus {
  if (node.status === 'revoked') return 'revoked';
  return node.last_seen_at ? 'active' : 'enrolled';
}

export function nodeStatusLabel(status: NodeDisplayStatus): string {
  if (status === 'enrolled') return 'enrolled';
  if (status === 'active') return 'active';
  return 'revoked';
}

/** Human-friendly "12s ago" label used by the node status and heartbeat views. */
export function formatRelativeTime(iso: string | null | undefined): string {
  if (!iso) return 'Never';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return 'Unknown';

  const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (seconds < 5) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return 'Invalid date';
  return date.toLocaleString();
}
