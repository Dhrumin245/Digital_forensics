import { FormEvent, useEffect, useState } from "react";
import {
  api,
  CaseRecord,
  CaseStatus,
  EvidenceRecord,
  EvidenceType,
  UserProfile,
  UserRole,
  VerificationResult,
} from "./api";

type View = "overview" | "cases" | "evidence" | "verify" | "users";
interface Session {
  token: string;
  user: UserProfile;
}

const navItems: { id: View; label: string; icon: string }[] = [
  { id: "overview", label: "Overview", icon: "⌂" },
  { id: "cases", label: "Case register", icon: "▤" },
  { id: "evidence", label: "Evidence vault", icon: "◈" },
  { id: "verify", label: "Public verifier", icon: "✓" },
  { id: "users", label: "User directory", icon: "♙" },
];

function formatDate(value?: string | null) {
  return value
    ? new Intl.DateTimeFormat("en", {
        month: "short",
        day: "numeric",
        year: "numeric",
      }).format(new Date(value))
    : "—";
}
function formatSize(bytes: number) {
  if (!bytes) return "—";
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
  return `${Math.max(1, Math.round(bytes / 1000))} KB`;
}
function initials(name: string) {
  return name
    .split(" ")
    .map((part) => part[0])
    .slice(0, 2)
    .join("")
    .toUpperCase();
}
function shortHash(hash: string) {
  return `${hash.slice(0, 10)}...${hash.slice(-8)}`;
}

function App() {
  const [session, setSession] = useState<Session | null>(() => {
    const saved = sessionStorage.getItem("forensicchain_session");
    return saved ? JSON.parse(saved) : null;
  });
  const [view, setView] = useState<View>("overview");
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [selectedCase, setSelectedCase] = useState<CaseRecord | null>(null);
  const [evidence, setEvidence] = useState<EvidenceRecord[]>([]);
  const [users, setUsers] = useState<UserProfile[]>([]);
  const [loading, setLoading] = useState(false);
  const [notice, setNotice] = useState<{
    type: "error" | "success";
    text: string;
  } | null>(null);

  async function loadCases(token: string) {
    setLoading(true);
    setNotice(null);
    try {
      const result = await api.listCases(token);
      setCases(result.items);
      setSelectedCase((current) =>
        current
          ? result.items.find((item) => item.id === current.id) || null
          : result.items[0] || null,
      );
    } catch (error) {
      setNotice({
        type: "error",
        text: error instanceof Error ? error.message : "Could not load cases.",
      });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (session) void loadCases(session.token);
  }, [session]);
  useEffect(() => {
    if (!session || !selectedCase) {
      setEvidence([]);
      return;
    }
    setLoading(true);
    api
      .listEvidence(session.token, selectedCase.id)
      .then(setEvidence)
      .catch((error) =>
        setNotice({
          type: "error",
          text:
            error instanceof Error ? error.message : "Could not load evidence.",
        }),
      )
      .finally(() => setLoading(false));
  }, [session, selectedCase?.id]);
  useEffect(() => {
    if (!session || session.user.role !== "Admin" || view !== "users") return;
    setLoading(true);
    api
      .listUsers(session.token)
      .then(setUsers)
      .catch((error) =>
        setNotice({
          type: "error",
          text:
            error instanceof Error ? error.message : "Could not load users.",
        }),
      )
      .finally(() => setLoading(false));
  }, [session, view]);

  function signIn(next: Session) {
    sessionStorage.setItem("forensicchain_session", JSON.stringify(next));
    setSession(next);
  }
  function signOut() {
    sessionStorage.removeItem("forensicchain_session");
    setSession(null);
    setCases([]);
    setEvidence([]);
  }
  if (!session) return <Login onLogin={signIn} />;

  const tampered = evidence.filter(
    (item) => item.integrity_status === "tampered",
  );
  const pending = evidence.filter(
    (item) => item.integrity_status === "pending",
  );
  return (
    <div className="app-shell">
      <Sidebar
        user={session.user}
        active={view}
        onNavigate={setView}
        onSignOut={signOut}
      />
      <main className="main-area">
        <header className="topbar">
          <div>
            <p className="eyebrow">FORENSIC OPERATIONS / LIVE DATABASE</p>
            <h1>
              {view === "overview"
                ? "Command overview"
                : navItems.find((item) => item.id === view)?.label}
            </h1>
          </div>
          <div className="connection">
            <span className="pulse" /> API connected{" "}
            <span className="connection-url">localhost:8000</span>
          </div>
        </header>
        <div className="page-content">
          {notice && (
            <div className={`notice ${notice.type}`}>
              <strong>
                {notice.type === "error" ? "Request issue" : "Saved"}
              </strong>
              <span>{notice.text}</span>
              <button onClick={() => setNotice(null)}>Dismiss</button>
            </div>
          )}
          {view === "overview" && (
            <Overview
              cases={cases}
              evidence={evidence}
              tampered={tampered}
              pending={pending}
              loading={loading}
              onNavigate={setView}
              onSelectCase={(item) => {
                setSelectedCase(item);
                setView("evidence");
              }}
            />
          )}
          {view === "cases" && (
            <CasesView
              cases={cases}
              selectedCase={selectedCase}
              loading={loading}
              token={session.token}
              user={session.user}
              onRefresh={() => loadCases(session.token)}
              onSelect={(item) => setSelectedCase(item)}
              onCreated={(item) => {
                setCases((current) => [item, ...current]);
                setSelectedCase(item);
                setNotice({
                  type: "success",
                  text: `${item.case_number} is now stored in the database.`,
                });
              }}
            />
          )}
          {view === "evidence" && (
            <EvidenceView
              cases={cases}
              selectedCase={selectedCase}
              evidence={evidence}
              loading={loading}
              token={session.token}
              canUpload={session.user.role === "LabTechnician"}
              onSelectCase={setSelectedCase}
              onUploaded={(item) => {
                setEvidence((current) => [item, ...current]);
                setNotice({
                  type: "success",
                  text: `${item.filename} was registered and hashed by the API.`,
                });
              }}
            />
          )}
          {view === "verify" && <VerifyView />}
          {view === "users" && session.user.role === "Admin" && (
            <UsersView
              users={users}
              loading={loading}
              token={session.token}
              currentUserId={session.user.id}
              onCreated={(user) => {
                setUsers((current) => [user, ...current]);
                setNotice({
                  type: "success",
                  text: `${user.full_name} can now sign in as ${user.role}.`,
                });
              }}
              onUpdated={(user) =>
                setUsers((current) =>
                  current.map((item) => (item.id === user.id ? user : item)),
                )
              }
            />
          )}
        </div>
      </main>
    </div>
  );
}

function Login({ onLogin }: { onLogin: (session: Session) => void }) {
  const [email, setEmail] = useState("admin@forensicchain.dev");
  const [password, setPassword] = useState("");
  const [selectedRole, setSelectedRole] = useState<UserRole>("Admin");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const token = await api.login(email, password);
      const user = await api.me(token.access_token);
      if (user.role !== selectedRole) {
        throw new Error(
          `This account is assigned to ${user.role}. Select that role and try again.`,
        );
      }
      onLogin({ token: token.access_token, user });
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "The backend could not be reached.",
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="login-page">
      <div className="login-visual">
        <div className="brand-mark">FC</div>
        <p className="eyebrow">DIGITAL FORENSICS / EVIDENCE INTEGRITY</p>
        <h1>Evidence that holds up under scrutiny.</h1>
        <p>
          One workspace for cases, chain of custody, and verifiable evidence
          records backed by the ForensicChain API.
        </p>
        <div className="login-metric">
          <span>SHA-256 integrity</span>
          <strong>SERVER-SIDE</strong>
        </div>
      </div>
      <form className="login-panel" onSubmit={submit}>
        <div className="brand-lockup">
          <span className="brand-dot" /> ForensicChain
        </div>
        <p className="eyebrow">SECURE ACCESS</p>
        <h2>Sign in to your workspace</h2>
        <p className="muted">
          Use an account from the connected backend. Demo credentials are not
          accepted.
        </p>
        {error && <div className="form-error">{error}</div>}
        <label>
          Email
          <input
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            placeholder="you@forensics.local"
            required
          />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder="Your password"
            required
          />
        </label>
        <label>
          Sign in as
          <select
            value={selectedRole}
            onChange={(event) =>
              setSelectedRole(event.target.value as UserRole)
            }
          >
            <option value="Admin">Administrator</option>
            <option value="CaseManager">Case Manager</option>
            <option value="LabTechnician">Lab Technician</option>
            <option value="Examiner">Examiner</option>
            <option value="LegalReviewer">Legal Reviewer</option>
          </select>
          <small className="field-help">
            This confirms your account role. It does not grant access.
          </small>
        </label>
        <button className="primary wide" disabled={busy}>
          {busy ? "Authenticating..." : "Connect to workspace"} <span>→</span>
        </button>
        <p className="login-foot">
          Your session is stored only in this browser tab.
        </p>
      </form>
    </div>
  );
}

function Sidebar({
  user,
  active,
  onNavigate,
  onSignOut,
}: {
  user: UserProfile;
  active: View;
  onNavigate: (view: View) => void;
  onSignOut: () => void;
}) {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="brand-mark small">FC</div>
        <div>
          <strong>ForensicChain</strong>
          <small>Integrity operations</small>
        </div>
      </div>
      <div className="side-label">Workspace</div>
      <nav>
        {navItems
          .filter((item) => item.id !== "users" || user.role === "Admin")
          .map((item) => (
            <button
              key={item.id}
              className={active === item.id ? "active" : ""}
              onClick={() => onNavigate(item.id)}
            >
              <span className="nav-icon">{item.icon}</span>
              {item.label}
            </button>
          ))}
      </nav>
      <div className="sidebar-bottom">
        <div className="user-card">
          <div className="avatar">{initials(user.full_name)}</div>
          <div>
            <strong>{user.full_name}</strong>
            <small>{user.role}</small>
          </div>
        </div>
        <button className="signout" onClick={onSignOut}>
          Sign out <span>↗</span>
        </button>
      </div>
    </aside>
  );
}

function Overview({
  cases,
  evidence,
  tampered,
  pending,
  loading,
  onNavigate,
  onSelectCase,
}: {
  cases: CaseRecord[];
  evidence: EvidenceRecord[];
  tampered: EvidenceRecord[];
  pending: EvidenceRecord[];
  loading: boolean;
  onNavigate: (view: View) => void;
  onSelectCase: (item: CaseRecord) => void;
}) {
  const active = cases.filter((item) => item.status === "active").length;
  return (
    <section className="screen">
      <div className="hero-row">
        <div>
          <p className="eyebrow">OPERATIONS SNAPSHOT</p>
          <h2>Good morning, investigator.</h2>
          <p className="muted">
            A current view of the records your account can access.
          </p>
        </div>
        <button className="secondary" onClick={() => onNavigate("cases")}>
          Open case register <span>→</span>
        </button>
      </div>
      <div className="metric-grid">
        <Metric
          label="Accessible cases"
          value={cases.length}
          note={`${active} active`}
        />
        <Metric
          label="Evidence in view"
          value={evidence.length}
          note="Selected case"
        />
        <Metric
          label="Integrity alerts"
          value={tampered.length}
          note={tampered.length ? "Requires review" : "No active alerts"}
          tone={tampered.length ? "danger" : "good"}
        />
        <Metric
          label="Pending custody"
          value={pending.length}
          note="Awaiting acceptance"
        />
      </div>
      <div className="content-grid">
        <div className="panel">
          <PanelHead
            title="Recent case register"
            action={
              <button
                className="text-button"
                onClick={() => onNavigate("cases")}
              >
                View all →
              </button>
            }
          />
          <div className="case-list">
            {loading && !cases.length ? (
              <Loading />
            ) : (
              cases.slice(0, 5).map((item) => (
                <button
                  className="case-row"
                  key={item.id}
                  onClick={() => onSelectCase(item)}
                >
                  <span className="case-sigil">
                    {item.case_number.slice(-2)}
                  </span>
                  <span className="case-main">
                    <strong>{item.title}</strong>
                    <small>
                      {item.case_number} · updated {formatDate(item.updated_at)}
                    </small>
                  </span>
                  <Status status={item.status} />
                  <span className="row-arrow">→</span>
                </button>
              ))
            )}
            {!loading && !cases.length && (
              <Empty text="No cases are available for this account." />
            )}
          </div>
        </div>
        <div className="panel accent-panel">
          <PanelHead title="Integrity posture" />
          <div className="posture">
            <div
              className={`posture-icon ${tampered.length ? "danger" : "good"}`}
            >
              {tampered.length ? "!" : "✓"}
            </div>
            <div>
              <strong>
                {tampered.length
                  ? `${tampered.length} item needs attention`
                  : "All observed hashes are clear"}
              </strong>
              <p>
                {tampered.length
                  ? "Review the evidence vault before moving custody."
                  : "Live integrity checks are reported by the API."}
              </p>
            </div>
          </div>
          <button
            className="secondary full"
            onClick={() => onNavigate("evidence")}
          >
            Review evidence vault
          </button>
        </div>
      </div>
    </section>
  );
}

function Metric({
  label,
  value,
  note,
  tone = "",
}: {
  label: string;
  value: number;
  note: string;
  tone?: string;
}) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong className={tone}>{value}</strong>
      <small>{note}</small>
    </div>
  );
}
function PanelHead({
  title,
  action,
}: {
  title: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="panel-head">
      <h3>{title}</h3>
      {action}
    </div>
  );
}
function Status({ status }: { status: string }) {
  return <span className={`status ${status}`}>{status.replace("_", " ")}</span>;
}
function Loading() {
  return (
    <div className="loading">
      <span /> Loading records from API...
    </div>
  );
}
function Empty({ text }: { text: string }) {
  return <div className="empty">{text}</div>;
}

function CasesView({
  cases,
  selectedCase,
  loading,
  token,
  user,
  onRefresh,
  onSelect,
  onCreated,
}: {
  cases: CaseRecord[];
  selectedCase: CaseRecord | null;
  loading: boolean;
  token: string;
  user: UserProfile;
  onRefresh: () => void;
  onSelect: (item: CaseRecord) => void;
  onCreated: (item: CaseRecord) => void;
}) {
  const [showCreate, setShowCreate] = useState(false);
  const canCreate = user.role === "CaseManager";
  return (
    <section className="screen">
      <div className="section-head">
        <div>
          <p className="eyebrow">CASE REGISTER</p>
          <h2>Cases</h2>
          <p className="muted">
            Records are loaded directly from PostgreSQL through the API.
          </p>
        </div>
        <div className="actions">
          <button className="secondary" onClick={onRefresh}>
            ↻ Refresh
          </button>
          {canCreate && (
            <button className="primary" onClick={() => setShowCreate(true)}>
              ＋ New case
            </button>
          )}
        </div>
      </div>
      {selectedCase && (
        <div className="selected-strip">
          <span>Selected</span>
          <strong>{selectedCase.case_number}</strong>
          <em>{selectedCase.title}</em>
          <Status status={selectedCase.status} />
        </div>
      )}
      <div className="panel table-panel">
        <table>
          <thead>
            <tr>
              <th>Case</th>
              <th>Status</th>
              <th>Evidence</th>
              <th>Assignments</th>
              <th>Updated</th>
            </tr>
          </thead>
          <tbody>
            {cases.map((item) => (
              <tr
                className={selectedCase?.id === item.id ? "selected" : ""}
                key={item.id}
                onClick={() => onSelect(item)}
              >
                <td>
                  <strong>{item.title}</strong>
                  <small>{item.case_number}</small>
                </td>
                <td>
                  <Status status={item.status} />
                </td>
                <td>{item.evidence_count}</td>
                <td>{item.assignment_count}</td>
                <td>{formatDate(item.updated_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {loading && !cases.length && <Loading />}
        {!loading && !cases.length && (
          <Empty text="No cases are available for this account." />
        )}
      </div>
      {showCreate && (
        <CreateCase
          token={token}
          onClose={() => setShowCreate(false)}
          onCreated={(item) => {
            onCreated(item);
            setShowCreate(false);
          }}
        />
      )}
    </section>
  );
}

function CreateCase({
  token,
  onClose,
  onCreated,
}: {
  token: string;
  onClose: () => void;
  onCreated: (item: CaseRecord) => void;
}) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      onCreated(await api.createCase(token, { title, description }));
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Could not create the case.",
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="modal-backdrop">
      <form className="modal" onSubmit={submit}>
        <div className="modal-head">
          <div>
            <p className="eyebrow">NEW RECORD</p>
            <h3>Create case</h3>
          </div>
          <button type="button" className="close" onClick={onClose}>
            ×
          </button>
        </div>
        {error && <div className="form-error">{error}</div>}
        <label>
          Case title
          <input
            value={title}
            onChange={(event) => setTitle(event.target.value)}
            required
            maxLength={300}
            placeholder="e.g. Endpoint compromise review"
          />
        </label>
        <label>
          Description
          <textarea
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            maxLength={2000}
            placeholder="What is this investigation about?"
          />
        </label>
        <div className="modal-actions">
          <button type="button" className="secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="primary" disabled={busy}>
            {busy ? "Creating..." : "Create case"}
          </button>
        </div>
      </form>
    </div>
  );
}

function EvidenceView({
  cases,
  selectedCase,
  evidence,
  loading,
  token,
  canUpload,
  onSelectCase,
  onUploaded,
}: {
  cases: CaseRecord[];
  selectedCase: CaseRecord | null;
  evidence: EvidenceRecord[];
  loading: boolean;
  token: string;
  canUpload: boolean;
  onSelectCase: (item: CaseRecord) => void;
  onUploaded: (item: EvidenceRecord) => void;
}) {
  const [showUpload, setShowUpload] = useState(false);
  return (
    <section className="screen">
      <div className="section-head">
        <div>
          <p className="eyebrow">EVIDENCE VAULT</p>
          <h2>Evidence registry</h2>
          <p className="muted">
            Hashes and integrity status returned from the connected database.
          </p>
        </div>
        {canUpload && selectedCase && (
          <button className="primary" onClick={() => setShowUpload(true)}>
            ＋ Register evidence
          </button>
        )}
      </div>
      <div className="toolbar">
        <label>
          Case
          <select
            value={selectedCase?.id || ""}
            onChange={(event) => {
              const next = cases.find((item) => item.id === event.target.value);
              if (next) onSelectCase(next);
            }}
          >
            <option value="" disabled>
              Select a case
            </option>
            {cases.map((item) => (
              <option key={item.id} value={item.id}>
                {item.case_number} · {item.title}
              </option>
            ))}
          </select>
        </label>
        {selectedCase && (
          <div className="toolbar-context">
            <span className="case-sigil">
              {selectedCase.case_number.slice(-2)}
            </span>
            <span>
              <strong>{selectedCase.title}</strong>
              <small>{selectedCase.evidence_count} items registered</small>
            </span>
          </div>
        )}
      </div>
      {!selectedCase ? (
        <div className="panel">
          <Empty text="Select a case to inspect its evidence." />
        </div>
      ) : (
        <div className="panel table-panel">
          <table>
            <thead>
              <tr>
                <th>Artifact</th>
                <th>Type</th>
                <th>Integrity</th>
                <th>SHA-256</th>
                <th>Size</th>
                <th>Uploaded</th>
              </tr>
            </thead>
            <tbody>
              {evidence.map((item) => (
                <tr key={item.id}>
                  <td>
                    <strong>{item.filename}</strong>
                    <small>{item.description}</small>
                  </td>
                  <td>{item.evidence_type.replace("_", " ")}</td>
                  <td>
                    <Status status={item.integrity_status} />
                  </td>
                  <td>
                    <code title={item.sha256_hash}>
                      {shortHash(item.sha256_hash)}
                    </code>
                  </td>
                  <td>{formatSize(item.file_size_bytes)}</td>
                  <td>{formatDate(item.uploaded_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {loading && <Loading />}
          {!loading && !evidence.length && (
            <Empty text="This case has no evidence registered yet." />
          )}
        </div>
      )}
      {showUpload && selectedCase && (
        <UploadEvidence
          token={token}
          caseId={selectedCase.id}
          onClose={() => setShowUpload(false)}
          onUploaded={(item) => {
            onUploaded(item);
            setShowUpload(false);
          }}
        />
      )}
    </section>
  );
}

function UploadEvidence({
  token,
  caseId,
  onClose,
  onUploaded,
}: {
  token: string;
  caseId: string;
  onClose: () => void;
  onUploaded: (item: EvidenceRecord) => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [description, setDescription] = useState("");
  const [type, setType] = useState<EvidenceType>("file");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!file) {
      setError("Choose a file first.");
      return;
    }
    setBusy(true);
    try {
      onUploaded(
        await api.uploadEvidence(token, caseId, file, description, type),
      );
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Could not upload evidence.",
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="modal-backdrop">
      <form className="modal" onSubmit={submit}>
        <div className="modal-head">
          <div>
            <p className="eyebrow">SERVER-SIDE HASHING</p>
            <h3>Register evidence</h3>
          </div>
          <button type="button" className="close" onClick={onClose}>
            ×
          </button>
        </div>
        <p className="muted">
          The API reads the file, stores it, and computes SHA-256. The browser
          never supplies the hash.
        </p>
        {error && <div className="form-error">{error}</div>}
        <label>
          Evidence file
          <input
            type="file"
            onChange={(event) => setFile(event.target.files?.[0] || null)}
            required
          />
        </label>
        <label>
          Evidence type
          <select
            value={type}
            onChange={(event) => setType(event.target.value as EvidenceType)}
          >
            {[
              "file",
              "disk_image",
              "memory_dump",
              "log_file",
              "network_capture",
              "mobile_backup",
              "other",
            ].map((item) => (
              <option key={item}>{item.replace("_", " ")}</option>
            ))}
          </select>
        </label>
        <label>
          Description
          <textarea
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            required
            placeholder="Describe what this artifact represents"
          />
        </label>
        <div className="modal-actions">
          <button type="button" className="secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="primary" disabled={busy}>
            {busy ? "Uploading..." : "Register artifact"}
          </button>
        </div>
      </form>
    </div>
  );
}

function UsersView({
  users,
  loading,
  token,
  currentUserId,
  onCreated,
  onUpdated,
}: {
  users: UserProfile[];
  loading: boolean;
  token: string;
  currentUserId: string;
  onCreated: (user: UserProfile) => void;
  onUpdated: (user: UserProfile) => void;
}) {
  const [showCreate, setShowCreate] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [draftRole, setDraftRole] = useState<Record<string, UserRole>>({});

  async function toggleActive(user: UserProfile) {
    setBusyId(user.id);
    setError("");
    try {
      onUpdated(
        await api.updateUser(token, user.id, { is_active: !user.is_active }),
      );
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Could not update the user.",
      );
    } finally {
      setBusyId(null);
    }
  }

  async function changeRole(user: UserProfile) {
    const role = draftRole[user.id];
    if (!role || role === user.role) return;
    setBusyId(user.id);
    setError("");
    try {
      onUpdated(await api.updateUser(token, user.id, { role }));
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Could not update the role.",
      );
    } finally {
      setBusyId(null);
    }
  }

  return (
    <section className="screen">
      <div className="section-head">
        <div>
          <p className="eyebrow">ADMINISTRATION</p>
          <h2>User directory</h2>
          <p className="muted">
            Create real accounts for Case Managers, Lab Technicians, Examiners,
            and Legal Reviewers.
          </p>
        </div>
        <button className="primary" onClick={() => setShowCreate(true)}>
          ＋ Add user
        </button>
      </div>
      {error && <div className="form-error">{error}</div>}
      <div className="panel table-panel">
        <table>
          <thead>
            <tr>
              <th>Person</th>
              <th>Role</th>
              <th>Status</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id}>
                <td>
                  <strong>{user.full_name}</strong>
                  <small>{user.email}</small>
                </td>
                <td>
                  <select
                    value={draftRole[user.id] || user.role}
                    disabled={busyId === user.id || user.id === currentUserId}
                    onChange={(event) =>
                      setDraftRole((current) => ({
                        ...current,
                        [user.id]: event.target.value as UserRole,
                      }))
                    }
                  >
                    <option value="Admin">Administrator</option>
                    <option value="CaseManager">Case Manager</option>
                    <option value="LabTechnician">Lab Technician</option>
                    <option value="Examiner">Examiner</option>
                    <option value="LegalReviewer">Legal Reviewer</option>
                  </select>
                </td>
                <td>
                  <Status status={user.is_active ? "active" : "closed"} />
                </td>
                <td>{formatDate(user.created_at)}</td>
                <td>
                  <div className="table-actions">
                    <button
                      className="text-button"
                      disabled={busyId === user.id || user.id === currentUserId}
                      onClick={() => void changeRole(user)}
                    >
                      Save role
                    </button>
                    <button
                      className="text-button"
                      disabled={busyId === user.id || user.id === currentUserId}
                      onClick={() => void toggleActive(user)}
                    >
                      {user.is_active ? "Deactivate" : "Activate"}
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {loading && <Loading />}
        {!loading && !users.length && (
          <Empty text="No users were returned by the API." />
        )}
      </div>
      {showCreate && (
        <CreateUser
          token={token}
          onClose={() => setShowCreate(false)}
          onCreated={(user) => {
            onCreated(user);
            setShowCreate(false);
          }}
        />
      )}
    </section>
  );
}

function CreateUser({
  token,
  onClose,
  onCreated,
}: {
  token: string;
  onClose: () => void;
  onCreated: (user: UserProfile) => void;
}) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<UserRole>("Examiner");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      onCreated(
        await api.createUser(token, { full_name: name, email, password, role }),
      );
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Could not create the user.",
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="modal-backdrop">
      <form className="modal" onSubmit={submit}>
        <div className="modal-head">
          <div>
            <p className="eyebrow">NEW ACCOUNT</p>
            <h3>Add workspace user</h3>
          </div>
          <button type="button" className="close" onClick={onClose}>
            ×
          </button>
        </div>
        <p className="muted">
          The selected role controls what this person can do after signing in.
        </p>
        {error && <div className="form-error">{error}</div>}
        <label>
          Full name
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            required
            maxLength={200}
            placeholder="Jordan Lee"
          />
        </label>
        <label>
          Email
          <input
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            required
            placeholder="jordan@example.com"
          />
        </label>
        <label>
          Workspace role
          <select
            value={role}
            onChange={(event) => setRole(event.target.value as UserRole)}
          >
            <option value="CaseManager">Case Manager</option>
            <option value="LabTechnician">Lab Technician</option>
            <option value="Examiner">Examiner</option>
            <option value="LegalReviewer">Legal Reviewer</option>
            <option value="Admin">Administrator</option>
          </select>
        </label>
        <label>
          Temporary password
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            minLength={12}
            required
            placeholder="At least 12 characters"
          />
        </label>
        <div className="modal-actions">
          <button type="button" className="secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="primary" disabled={busy}>
            {busy ? "Creating..." : "Create account"}
          </button>
        </div>
      </form>
    </div>
  );
}

function VerifyView() {
  const [hash, setHash] = useState("");
  const [result, setResult] = useState<VerificationResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setResult(null);
    try {
      setResult(await api.verifyHash(hash.trim()));
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Verification failed.",
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="screen verify-screen">
      <div className="verify-intro">
        <p className="eyebrow">PUBLIC VERIFICATION PORTAL</p>
        <h2>Verify an evidence hash.</h2>
        <p>
          Query the unauthenticated verification endpoint without exposing the
          evidence file itself.
        </p>
        <form onSubmit={submit}>
          <input
            value={hash}
            onChange={(event) => setHash(event.target.value)}
            placeholder="64-character SHA-256 hash"
            pattern="[a-fA-F0-9]{64}"
            required
          />
          <button className="primary" disabled={busy}>
            {busy ? "Checking..." : "Verify hash"}
          </button>
        </form>
      </div>
      {error && <div className="form-error">{error}</div>}
      {result && (
        <div
          className={`verification-result ${result.status === "verified" ? "good" : ""}`}
        >
          <div className="result-icon">
            {result.status === "verified" ? "✓" : "?"}
          </div>
          <div>
            <p className="eyebrow">API RESPONSE</p>
            <h3>
              {result.status === "verified"
                ? "Hash verified"
                : "No registered evidence found"}
            </h3>
            <p className="muted">
              {result.filename ||
                "The hash is not associated with a registered artifact."}
            </p>
            <code>{result.hash}</code>
            {result.first_registered_at && (
              <small>
                First registered {formatDate(result.first_registered_at)} ·{" "}
                {result.custody_transfer_count || 0} custody transfers
              </small>
            )}
          </div>
        </div>
      )}
    </section>
  );
}

export default App;
