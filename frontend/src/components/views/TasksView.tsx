import React, { useEffect, useState } from 'react';
import {
  ListTodo,
  Plus,
  Play,
  XCircle,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  ShieldCheck,
  ShieldAlert,
  ArrowRight,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { getTasks, submitTask, cancelTask } from '../../services/api';
import { Task } from '../../types/api';
import { Badge } from '../common/Badge';
import { Modal } from '../common/Modal';

export const TasksView: React.FC = () => {
  const { isDemoMode, role, hasPermission } = useAuth();
  const [tasks, setTasks] = useState<Task[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [statusFilter, setStatusFilter] = useState<string>('');

  // Submit task modal
  const [isSubmitOpen, setIsSubmitOpen] = useState<boolean>(false);
  const [taskType, setTaskType] = useState<'checksum' | 'word_count' | 'sensor_average'>('checksum');
  const [priority, setPriority] = useState<number>(2);
  const [payloadText, setPayloadText] = useState<string>('{\n  "target_file": "firmware-v3.bin",\n  "algorithm": "sha256"\n}');
  const [idempotencyKey, setIdempotencyKey] = useState<string>(() => crypto.randomUUID());
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  // Selected task detail
  const [selectedTask, setSelectedTask] = useState<Task | null>(null);

  const fetchTaskList = async () => {
    setIsLoading(true);
    try {
      const res = await getTasks({ status: statusFilter || undefined }, isDemoMode);
      setTasks(res.results || []);
    } catch (err) {
      console.error('Failed to load tasks:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchTaskList();
  }, [isDemoMode, statusFilter]);

  const handleTaskTypeChange = (type: 'checksum' | 'word_count' | 'sensor_average') => {
    setTaskType(type);
    if (type === 'checksum') {
      setPayloadText('{\n  "target_file": "firmware-v3.bin",\n  "algorithm": "sha256"\n}');
    } else if (type === 'word_count') {
      setPayloadText('{\n  "document_ref": "audit-report-2026.txt",\n  "filter_stops": true\n}');
    } else if (type === 'sensor_average') {
      setPayloadText('{\n  "sensor_ids": [201, 202, 203],\n  "sampling_rate_hz": 100\n}');
    }
  };

  const handleSubmitTask = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setSubmitError(null);

    let parsedPayload: Record<string, unknown>;
    try {
      parsedPayload = JSON.parse(payloadText);
    } catch {
      setSubmitError('Payload must be valid JSON.');
      setIsSubmitting(false);
      return;
    }

    try {
      if (isDemoMode) {
        // Check for duplicate idempotency key simulation
        if (tasks.some((t) => t.idempotency_key === idempotencyKey)) {
          throw new Error('409 DUPLICATE_SUBMISSION: Idempotency-Key already registered for an existing task.');
        }

        const newTask: Task = {
          id: `task-${Date.now()}`,
          task_type: taskType,
          payload: parsedPayload,
          priority,
          status: 'queued',
          assigned_node: null,
          attempts: 0,
          max_attempts: 3,
          idempotency_key: idempotencyKey,
          created_by: 'operator1',
          created_at: new Date().toISOString(),
        };
        setTasks([newTask, ...tasks]);
      } else {
        await submitTask({
          task_type: taskType,
          payload: parsedPayload,
          priority,
          idempotency_key: idempotencyKey,
        });
        await fetchTaskList();
      }

      setIsSubmitOpen(false);
      setIdempotencyKey(crypto.randomUUID());
    } catch (err: any) {
      setSubmitError(err.message || 'Task submission failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCancelTask = async (taskId: string) => {
    if (!confirm('Are you sure you want to cancel this task?')) return;
    try {
      if (isDemoMode) {
        setTasks((prev) =>
          prev.map((t) => (t.id === taskId ? { ...t, status: 'cancelled' } : t))
        );
      } else {
        await cancelTask(taskId);
        await fetchTaskList();
      }
      setSelectedTask(null);
    } catch (err: any) {
      alert(err.message || 'Task cancellation failed');
    }
  };

  const canSubmit = role === 'admin' || role === 'operator' || hasPermission('tasks.submit');

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <ListTodo className="w-5 h-5 text-teal-400" />
            Task Dispatch & Execution Queue
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Tasks are dispatched strictly to trusted nodes (trust score &gt;= policy threshold) and returned encrypted.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={fetchTaskList}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-slate-300 hover:text-white text-xs font-medium"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>
          {canSubmit && (
            <button
              onClick={() => {
                setIsSubmitOpen(true);
                setSubmitError(null);
                setIdempotencyKey(crypto.randomUUID());
              }}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium transition-colors shadow-sm"
            >
              <Plus className="w-4 h-4" />
              <span>Submit Task (FR-3)</span>
            </button>
          )}
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between gap-4">
        <div className="flex items-center gap-2 text-xs text-slate-400">
          <span>Filter Status:</span>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-teal-500"
          >
            <option value="">All Tasks</option>
            <option value="queued">Queued</option>
            <option value="assigned">Assigned</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
            <option value="cancelled">Cancelled</option>
          </select>
        </div>

        <div className="text-xs text-slate-500 font-mono">
          Scheduler Rule: Only active nodes meeting the trust threshold are assigned tasks.
        </div>
      </div>

      {/* Tasks Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px]">
              <tr>
                <th className="py-3 px-4">Task ID</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Priority</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Assigned Node</th>
                <th className="py-3 px-4">Attempts</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {tasks.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    {isLoading ? 'Loading tasks...' : 'No tasks match criteria.'}
                  </td>
                </tr>
              ) : (
                tasks.map((task) => (
                  <tr
                    key={task.id}
                    onClick={() => setSelectedTask(task)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                  >
                    <td className="py-3.5 px-4 font-mono font-medium text-slate-200">
                      {task.id}
                    </td>
                    <td className="py-3.5 px-4 font-mono uppercase text-[11px] text-teal-300">
                      {task.task_type}
                    </td>
                    <td className="py-3.5 px-4 font-mono">
                      <span
                        className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                          task.priority === 1
                            ? 'bg-rose-950 text-rose-300 border border-rose-800'
                            : 'bg-slate-950 text-slate-300 border border-slate-800'
                        }`}
                      >
                        P{task.priority}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <Badge label={task.status} />
                    </td>
                    <td className="py-3.5 px-4 font-mono text-[11px] text-slate-400">
                      {task.assigned_node ? task.assigned_node.slice(0, 12) + '...' : 'Pending'}
                    </td>
                    <td className="py-3.5 px-4 font-mono text-[11px] text-slate-400">
                      {task.attempts}/{task.max_attempts}
                    </td>
                    <td className="py-3.5 px-4 text-right text-teal-400 group-hover:text-teal-300">
                      <span className="text-xs font-mono flex items-center justify-end gap-1">
                        View <ArrowRight className="w-3 h-3" />
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Task Detail Modal */}
      {selectedTask && (
        <Modal
          isOpen={!!selectedTask}
          onClose={() => setSelectedTask(null)}
          title={`Task Inspection: ${selectedTask.id}`}
          maxWidth="lg"
        >
          <div className="space-y-4 text-xs">
            <div className="grid grid-cols-2 gap-3 p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono">
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Status</span>
                <Badge label={selectedTask.status} />
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Priority</span>
                <span className="text-slate-200">Priority {selectedTask.priority}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Assigned Node</span>
                <span className="text-slate-200 truncate block">
                  {selectedTask.assigned_node || 'Unassigned (In queue)'}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Attempts</span>
                <span className="text-slate-200">
                  {selectedTask.attempts} of {selectedTask.max_attempts} max attempts
                </span>
              </div>
            </div>

            {/* Payload box */}
            <div>
              <span className="text-slate-400 text-xs font-mono uppercase block mb-1">
                Validated Task Payload (Max 16 KB)
              </span>
              <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-slate-300 font-mono text-[11px] overflow-x-auto whitespace-pre-wrap select-all">
                {JSON.stringify(selectedTask.payload, null, 2)}
              </pre>
            </div>

            {/* Cryptographic Result Status */}
            {selectedTask.status === 'completed' && (
              <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-800/80 space-y-1">
                <div className="flex items-center gap-2 text-emerald-400 font-semibold">
                  <ShieldCheck className="w-4 h-4" />
                  <span>Decrypted Result Integrity Verified (AES-256-GCM)</span>
                </div>
                <p className="text-slate-300 text-[11px]">
                  Result payload decrypted successfully with authenticated tag verification (T4 check passed).
                </p>
              </div>
            )}

            {selectedTask.status === 'failed' && (
              <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-900/80 space-y-1">
                <div className="flex items-center gap-2 text-rose-400 font-semibold">
                  <ShieldAlert className="w-4 h-4" />
                  <span>Task Execution Failure / Tamper Detected</span>
                </div>
                <p className="text-rose-200 text-[11px]">
                  Worker failed integrity check or exceeded maximum retries (T3 stall / T4 tamper).
                </p>
              </div>
            )}

            {/* Metadata */}
            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 text-[11px] font-mono text-slate-400 space-y-1">
              <div>Idempotency-Key: {selectedTask.idempotency_key}</div>
              <div>Created: {new Date(selectedTask.created_at).toLocaleString()}</div>
            </div>

            {/* Cancel Action if queued or assigned */}
            {['queued', 'assigned'].includes(selectedTask.status) && (
              <div className="flex justify-end pt-2 border-t border-slate-800">
                <button
                  onClick={() => handleCancelTask(selectedTask.id)}
                  className="px-3 py-1.5 rounded-lg border border-rose-800 text-rose-400 hover:bg-rose-950 text-xs font-medium"
                >
                  Cancel Task Execution
                </button>
              </div>
            )}
          </div>
        </Modal>
      )}

      {/* Submit Task Modal */}
      {isSubmitOpen && (
        <Modal
          isOpen={isSubmitOpen}
          onClose={() => setIsSubmitOpen(false)}
          title="Submit New Edge Task (FR-3)"
        >
          <form onSubmit={handleSubmitTask} className="space-y-4">
            {submitError && (
              <div className="p-2.5 rounded bg-rose-900/50 border border-rose-700 text-rose-200 text-xs">
                {submitError}
              </div>
            )}

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Task Type (Allow-listed schema):
              </label>
              <select
                value={taskType}
                onChange={(e) =>
                  handleTaskTypeChange(
                    e.target.value as 'checksum' | 'word_count' | 'sensor_average'
                  )
                }
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-teal-500"
              >
                <option value="checksum">checksum (File SHA-256 verification)</option>
                <option value="word_count">word_count (Log tokenization)</option>
                <option value="sensor_average">sensor_average (Telemetry reduction)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Priority (1 = Highest, 5 = Lowest):
              </label>
              <div className="flex items-center gap-3">
                <input
                  type="range"
                  min="1"
                  max="5"
                  value={priority}
                  onChange={(e) => setPriority(Number(e.target.value))}
                  className="w-48 accent-teal-500"
                />
                <span className="font-mono text-xs font-bold text-teal-400">P{priority}</span>
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Payload JSON (validated server-side):
              </label>
              <textarea
                required
                rows={5}
                value={payloadText}
                onChange={(e) => setPayloadText(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-teal-500"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Idempotency-Key (prevents accidental duplication):
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  required
                  value={idempotencyKey}
                  onChange={(e) => setIdempotencyKey(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono"
                />
                <button
                  type="button"
                  onClick={() => setIdempotencyKey(crypto.randomUUID())}
                  className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-mono"
                >
                  New
                </button>
              </div>
              <span className="text-[10px] text-slate-500 mt-0.5 block">
                Submitting twice with the same key returns 409 DUPLICATE_SUBMISSION (T-final test).
              </span>
            </div>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setIsSubmitOpen(false)}
                className="px-4 py-2 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSubmitting}
                className="px-4 py-2 rounded-lg bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium transition-colors flex items-center gap-1.5"
              >
                <Play className="w-3.5 h-3.5" />
                <span>{isSubmitting ? 'Dispatching...' : 'Dispatch Task'}</span>
              </button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
};

