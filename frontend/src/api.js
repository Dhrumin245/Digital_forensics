/**
 * api.js — API client for the ForensicChain frontend.
 *
 * Every function maps 1-to-1 to an OpenAPI endpoint.
 * All functions throw { status, detail } on HTTP errors.
 * The UI catches these and falls back to MOCK data in demo mode.
 *
 * Usage:
 *   import { login, listCases, verifyHash } from './api';
 *   const token = (await login(email, password)).access_token;
 *   const cases = await listCases(token);
 */

const BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';

async function apiFetch(path, opts = {}, token = null) {
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(opts.headers || {}),
  };
  const res = await fetch(`${BASE}${path}`, { ...opts, headers });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw { status: res.status, detail: err.detail || 'Request failed' };
  }
  return res.status === 204 ? null : res.json();
}

// Helper for multipart form data (file uploads — no Content-Type header)
async function apiForm(path, formData, token) {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body: formData,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw { status: res.status, detail: err.detail || 'Upload failed' };
  }
  return res.json();
}

// ── Auth ──────────────────────────────────────────────────────────────────
export const login = (email, password) =>
  apiFetch('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) });

export const refreshToken = (refresh_token) =>
  apiFetch('/auth/refresh', { method: 'POST', body: JSON.stringify({ refresh_token }) });

export const getMe = (token) => apiFetch('/auth/me', {}, token);

// ── Cases ─────────────────────────────────────────────────────────────────
export const listCases = (token, status = null) =>
  apiFetch(`/cases${status ? `?status=${status}` : ''}`, {}, token);

export const getCase = (token, caseId) =>
  apiFetch(`/cases/${caseId}`, {}, token);

export const createCase = (token, body) =>
  apiFetch('/cases', { method: 'POST', body: JSON.stringify(body) }, token);

export const updateCase = (token, caseId, body) =>
  apiFetch(`/cases/${caseId}`, { method: 'PATCH', body: JSON.stringify(body) }, token);

export const listAssignments = (token, caseId) =>
  apiFetch(`/cases/${caseId}/assignments`, {}, token);

export const assignUser = (token, caseId, userId) =>
  apiFetch(`/cases/${caseId}/assignments`, {
    method: 'POST',
    body: JSON.stringify({ user_id: userId }),
  }, token);

export const removeAssignment = (token, caseId, userId) =>
  apiFetch(`/cases/${caseId}/assignments/${userId}`, { method: 'DELETE' }, token);

// ── Evidence ──────────────────────────────────────────────────────────────
export const listEvidence = (token, caseId, integrityStatus = null) =>
  apiFetch(`/cases/${caseId}/evidence${integrityStatus ? `?integrity_status=${integrityStatus}` : ''}`, {}, token);

export const getEvidence = (token, caseId, evidenceId) =>
  apiFetch(`/cases/${caseId}/evidence/${evidenceId}`, {}, token);

/**
 * Upload an evidence file.
 * @param {File} file          — raw File object from <input type="file">
 * @param {string} description — required text description
 * @param {string} evidenceType — enum: file, disk_image, memory_dump, etc.
 */
export const uploadEvidence = (token, caseId, file, description, evidenceType = 'file', acquisitionNotes = null) => {
  const fd = new FormData();
  fd.append('file', file);
  fd.append('description', description);
  fd.append('evidence_type', evidenceType);
  if (acquisitionNotes) fd.append('acquisition_notes', acquisitionNotes);
  return apiForm(`/cases/${caseId}/evidence`, fd, token);
};

/**
 * Import hashes from Autopsy/FTK CSV or JSON.
 */
export const importHashes = (token, caseId, file, acquisitionTool = null, forceDuplicates = false) => {
  const fd = new FormData();
  fd.append('file', file);
  if (acquisitionTool) fd.append('acquisition_tool', acquisitionTool);
  return apiForm(`/cases/${caseId}/evidence/import?force_duplicates=${forceDuplicates}`, fd, token);
};

export const downloadEvidence = (token, caseId, evidenceId) =>
  fetch(`${BASE}/cases/${caseId}/evidence/${evidenceId}/download`, {
    headers: { Authorization: `Bearer ${token}` },
  });

// ── Custody ───────────────────────────────────────────────────────────────
export const getCustodyChain = (token, caseId, evidenceId) =>
  apiFetch(`/cases/${caseId}/evidence/${evidenceId}/custody`, {}, token);

export const initiateTransfer = (token, caseId, evidenceId, toUserId, reason) =>
  apiFetch(`/cases/${caseId}/evidence/${evidenceId}/custody`, {
    method: 'POST',
    body: JSON.stringify({ to_user_id: toUserId, transfer_reason: reason }),
  }, token);

export const acceptTransfer = (token, caseId, evidenceId, transferId) =>
  apiFetch(`/cases/${caseId}/evidence/${evidenceId}/custody/${transferId}/accept`, { method: 'POST' }, token);

export const rejectTransfer = (token, caseId, evidenceId, transferId, reason) =>
  apiFetch(`/cases/${caseId}/evidence/${evidenceId}/custody/${transferId}/reject?reason=${encodeURIComponent(reason)}`, { method: 'POST' }, token);

// ── Tasks ─────────────────────────────────────────────────────────────────
export const listTasks = (token, caseId, params = {}) => {
  const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v)).toString();
  return apiFetch(`/cases/${caseId}/tasks${qs ? `?${qs}` : ''}`, {}, token);
};

export const createTask = (token, caseId, body) =>
  apiFetch(`/cases/${caseId}/tasks`, { method: 'POST', body: JSON.stringify(body) }, token);

export const updateTask = (token, caseId, taskId, body) =>
  apiFetch(`/cases/${caseId}/tasks/${taskId}`, { method: 'PATCH', body: JSON.stringify(body) }, token);

// ── Findings ──────────────────────────────────────────────────────────────
export const listFindings = (token, caseId, taskId) =>
  apiFetch(`/cases/${caseId}/tasks/${taskId}/findings`, {}, token);

export const createFinding = (token, caseId, taskId, evidenceId, title, content, attachments = []) => {
  const fd = new FormData();
  fd.append('evidence_id', evidenceId);
  fd.append('title', title);
  fd.append('content', content);
  attachments.forEach(f => fd.append('attachments', f));
  return apiForm(`/cases/${caseId}/tasks/${taskId}/findings`, fd, token);
};

// ── Reports ───────────────────────────────────────────────────────────────
export const listReports = (token, caseId) =>
  apiFetch(`/cases/${caseId}/reports`, {}, token);

export const createReport = (token, caseId, title, content) =>
  apiFetch(`/cases/${caseId}/reports`, { method: 'POST', body: JSON.stringify({ title, content }) }, token);

export const listVersions = (token, caseId, reportId) =>
  apiFetch(`/cases/${caseId}/reports/${reportId}/versions`, {}, token);

export const saveVersion = (token, caseId, reportId, content, changeSummary) =>
  apiFetch(`/cases/${caseId}/reports/${reportId}/versions`, {
    method: 'POST',
    body: JSON.stringify({ content, change_summary: changeSummary }),
  }, token);

export const lockReport = (token, caseId, reportId, versionNumber, reviewNotes) =>
  apiFetch(`/cases/${caseId}/reports/${reportId}/lock`, {
    method: 'POST',
    body: JSON.stringify({ version_number: versionNumber, review_notes: reviewNotes }),
  }, token);

export const diffVersions = (token, caseId, reportId, fromV, toV) =>
  apiFetch(`/cases/${caseId}/reports/${reportId}/versions/diff?from_version=${fromV}&to_version=${toV}`, {}, token);

export const generatePDF = (token, caseId, reportId) =>
  fetch(`${BASE}/cases/${caseId}/reports/${reportId}/pdf`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  });

// ── Verify portal (public — no auth required) ─────────────────────────────
export const verifyHash = (hash) => apiFetch(`/verify/${hash}`);
export const getPublicKey = () => apiFetch('/verify/public-key');

// ── Users ─────────────────────────────────────────────────────────────────
export const listUsers = (token, params = {}) => {
  const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined)).toString();
  return apiFetch(`/users${qs ? `?${qs}` : ''}`, {}, token);
};

export const createUser = (token, body) =>
  apiFetch('/users', { method: 'POST', body: JSON.stringify(body) }, token);

export const updateUser = (token, userId, body) =>
  apiFetch(`/users/${userId}`, { method: 'PATCH', body: JSON.stringify(body) }, token);

// ── Audit log ─────────────────────────────────────────────────────────────
export const queryAudit = (token, params = {}) => {
  const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v)).toString();
  return apiFetch(`/audit${qs ? `?${qs}` : ''}`, {}, token);
};

export const exportAuditCSV = (token, fromTs = null, toTs = null) => {
  const qs = new URLSearchParams({ ...(fromTs && { from_ts: fromTs }), ...(toTs && { to_ts: toTs }) }).toString();
  return fetch(`${BASE}/audit/export${qs ? `?${qs}` : ''}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
};
