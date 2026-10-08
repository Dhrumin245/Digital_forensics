export const API_BASE = import.meta.env.VITE_API_URL || '/api/v1';

export type CaseStatus = 'open' | 'active' | 'closed' | 'archived';
export type EvidenceType = 'disk_image' | 'file' | 'memory_dump' | 'log_file' | 'network_capture' | 'mobile_backup' | 'other';
export type IntegrityStatus = 'verified' | 'tampered' | 'pending' | 'unknown';
export type UserRole = 'CaseManager' | 'LabTechnician' | 'Examiner' | 'LegalReviewer' | 'Admin' | 'PublicVerifier';

export interface TokenResponse { access_token: string; refresh_token: string; token_type: string; expires_in: number }
export interface UserProfile { id: string; email: string; full_name: string; role: UserRole; is_active: boolean; created_at: string; last_login_at?: string | null }
export interface CaseRecord { id: string; case_number: string; title: string; description?: string | null; status: CaseStatus; created_by: string; created_at: string; updated_at: string; evidence_count: number; assignment_count: number }
export interface CaseListResponse { items: CaseRecord[]; total: number; page: number; page_size: number }
export interface EvidenceRecord { id: string; case_id: string; filename: string; file_size_bytes: number; mime_type: string; evidence_type: EvidenceType; sha256_hash: string; hash_source: string; acquisition_tool?: string | null; description: string; acquisition_notes?: string | null; uploaded_by: string; uploaded_at: string; current_custodian_id?: string | null; integrity_status: IntegrityStatus }
export interface VerificationResult { hash: string; status: string; evidence_id?: string | null; filename?: string | null; first_registered_at?: string | null; custody_transfer_count?: number; verified_at: string }

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) { super(message); this.status = status; }
}

async function request<T>(path: string, options: RequestInit = {}, token?: string): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json');
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const detail = typeof body.detail === 'string'
      ? body.detail
      : Array.isArray(body.detail)
        ? body.detail.map((item: { msg?: string }) => item.msg || 'Validation error').join('; ')
        : 'The API request failed.';
    throw new ApiError(response.status, detail);
  }
  return response.status === 204 ? (null as T) : response.json() as Promise<T>;
}

export const api = {
  login: (email: string, password: string) => request<TokenResponse>('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
  me: (token: string) => request<UserProfile>('/auth/me', {}, token),
  listUsers: (token: string) => request<UserProfile[]>('/users', {}, token),
  createUser: (token: string, body: { email: string; full_name: string; role: UserRole; password: string }) => request<UserProfile>('/users', { method: 'POST', body: JSON.stringify(body) }, token),
  updateUser: (token: string, userId: string, body: { role?: UserRole; is_active?: boolean; full_name?: string }) => request<UserProfile>(`/users/${userId}`, { method: 'PATCH', body: JSON.stringify(body) }, token),
  listCases: (token: string, status?: CaseStatus) => request<CaseListResponse>(`/cases${status ? `?status=${status}` : ''}`, {}, token),
  createCase: (token: string, body: { title: string; description?: string; reference_number?: string }) => request<CaseRecord>('/cases', { method: 'POST', body: JSON.stringify(body) }, token),
  listEvidence: (token: string, caseId: string) => request<EvidenceRecord[]>(`/cases/${caseId}/evidence`, {}, token),
  uploadEvidence: (token: string, caseId: string, file: File, description: string, evidenceType: EvidenceType) => {
    const body = new FormData(); body.append('file', file); body.append('description', description); body.append('evidence_type', evidenceType);
    return request<EvidenceRecord>(`/cases/${caseId}/evidence`, { method: 'POST', body }, token);
  },
  verifyHash: (hash: string) => request<VerificationResult>(`/verify/${hash}`),
};
