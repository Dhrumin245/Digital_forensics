const {useState,useEffect,useRef,useCallback}=React;
const API='http://localhost:8000/api/v1';

/* ── API wrapper — falls back to MOCK on any error ─────── */
async function api(path,opts={},token=null){
  try{
    const h={'Content-Type':'application/json',...(token?{Authorization:`Bearer ${token}`}:{}),...(opts.headers||{})};
    const r=await fetch(`${API}${path}`,{...opts,headers:h});
    if(!r.ok){const e=await r.json().catch(()=>({}));throw{status:r.status,detail:e.detail||'Request failed'};}
    return r.status===204?null:r.json();
  }catch(e){throw e;}
}

/* ── Mock data ──────────────────────────────────────────── */
const M={
  cases:[
    {id:'c1',case_number:'CASE-2024-00142',title:'Insider Trading Investigation',status:'active',created_at:'2024-11-01T09:00:00Z',evidence_count:6,assignment_count:3,description:'Investigation into suspected insider trading using corporate network access logs and workstation disk images.'},
    {id:'c2',case_number:'CASE-2024-00139',title:'Corporate Data Exfiltration',status:'open',created_at:'2024-10-28T14:30:00Z',evidence_count:2,assignment_count:1,description:'Suspected exfiltration of IP via USB devices and cloud storage uploads.'},
    {id:'c3',case_number:'CASE-2024-00121',title:'Ransomware Attack — Finance Dept',status:'closed',created_at:'2024-09-12T11:15:00Z',evidence_count:11,assignment_count:4,description:'Full forensic analysis of ransomware deployment vector and lateral movement within Finance department network.'},
  ],
  evidence:[
    {id:'e1',filename:'disk_image_workstation.dd',evidence_type:'disk_image',sha256_hash:'3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b',integrity_status:'verified',uploaded_at:'2024-11-01T10:05:00Z',file_size_bytes:2147483648,hash_source:'computed',description:'Full disk image of suspect workstation WS-0042',current_custodian_id:'u3'},
    {id:'e2',filename:'network_capture_nov01.pcap',evidence_type:'network_capture',sha256_hash:'8f14e45fceea167a5a36dedd4bea2543a18b8050b5d5b1be1e23e2b5b3ecf9d2',integrity_status:'verified',uploaded_at:'2024-11-01T10:22:00Z',file_size_bytes:524288000,hash_source:'computed',description:'Network traffic capture from perimeter firewall 09:00–17:00',current_custodian_id:'u2'},
    {id:'e3',filename:'memory_dump_srv01.mem',evidence_type:'memory_dump',sha256_hash:'a87ff679a2f3e71d9181a67b7542122ceea7ec23a48eba7b4df679c9ca1a4f99',integrity_status:'tampered',uploaded_at:'2024-11-02T08:44:00Z',file_size_bytes:17179869184,hash_source:'computed',description:'Memory dump of primary application server',current_custodian_id:'u3'},
    {id:'e4',filename:'autopsy_export.csv',evidence_type:'file',sha256_hash:'c4ca4238a0b923820dcc509a6f75849bc81e728d9d4c2f636f067f89cc14862c',integrity_status:'pending',uploaded_at:'2024-11-02T13:00:00Z',file_size_bytes:0,hash_source:'imported',description:'Hash import from Autopsy 4.20 analysis session',current_custodian_id:'u2'},
  ],
  custody:[
    {id:'t1',evidence_id:'e1',from_user:{id:'u2',full_name:'Sarah Chen',role:'LabTechnician'},to_user:{id:'u3',full_name:'Marcus Webb',role:'Examiner'},transfer_reason:'Assigned for disk image analysis — priority evidence',hash_at_transfer:'3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b',status:'accepted',initiated_at:'2024-11-01T10:30:00Z',accepted_at:'2024-11-01T10:35:00Z'},
    {id:'t2',evidence_id:'e1',from_user:{id:'u3',full_name:'Marcus Webb',role:'Examiner'},to_user:{id:'u4',full_name:'Diana Osei',role:'LegalReviewer'},transfer_reason:'Analysis complete — forwarding for legal review before court submission',hash_at_transfer:'3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b',status:'pending',initiated_at:'2024-11-04T14:00:00Z',accepted_at:null},
  ],
  tasks:[
    {id:'tk1',title:'Recover deleted files from disk image',status:'in_progress',assigned_to:{full_name:'Marcus Webb'},assigned_by:{full_name:'James Park'},due_date:'2024-11-10T00:00:00Z',evidence_ids:['e1'],created_at:'2024-11-01T11:00:00Z',findings_count:2},
    {id:'tk2',title:'Identify C2 traffic in network capture',status:'assigned',assigned_to:{full_name:'Marcus Webb'},assigned_by:{full_name:'James Park'},due_date:'2024-11-12T00:00:00Z',evidence_ids:['e2'],created_at:'2024-11-01T11:30:00Z',findings_count:0},
    {id:'tk3',title:'Process list extraction from memory dump',status:'completed',assigned_to:{full_name:'Marcus Webb'},assigned_by:{full_name:'James Park'},due_date:'2024-11-05T00:00:00Z',evidence_ids:['e3'],created_at:'2024-11-02T09:00:00Z',findings_count:3},
  ],
  findings:[
    {id:'f1',task_id:'tk1',evidence_id:'e1',title:'Deleted financial spreadsheets recovered',content:'Using Autopsy file carving, recovered 14 deleted Excel files from unallocated space. Files dated 2024-10-15 to 2024-10-28. Content includes quarterly earnings projections not yet publicly disclosed.',attachments:[],created_by:{full_name:'Marcus Webb'},created_at:'2024-11-02T14:00:00Z'},
    {id:'f2',task_id:'tk1',evidence_id:'e1',title:'Browser history shows pre-trade research',content:'Chrome browser history recovered shows 47 visits to SEC EDGAR for target companies in the 72-hour window before stock purchases. No plausible explanation from subject for this pattern.',attachments:[],created_by:{full_name:'Marcus Webb'},created_at:'2024-11-03T09:30:00Z'},
    {id:'f3',task_id:'tk3',evidence_id:'e3',title:'Suspicious process: svchost.exe -k netsvcs',content:'Memory analysis revealed a svchost.exe process running from %TEMP% instead of System32. MD5 of injected code matches known Mimikatz variant. Credentials likely extracted.',attachments:[],created_by:{full_name:'Marcus Webb'},created_at:'2024-11-02T16:00:00Z'},
  ],
  reports:[
    {id:'r1',title:'Disk Image Analysis — WS-0042',status:'court_ready',latest_version:3,court_ready_version:3,created_at:'2024-11-03T09:00:00Z',created_by:'Marcus Webb'},
    {id:'r2',title:'Network Traffic Analysis — Nov 1',status:'draft',latest_version:1,court_ready_version:null,created_at:'2024-11-04T11:00:00Z',created_by:'Marcus Webb'},
  ],
  report_versions:{
    r1:[
      {version_number:1,content_hash:'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',author:{full_name:'Marcus Webb'},saved_at:'2024-11-03T09:00:00Z',change_summary:'Initial version',is_court_ready:false},
      {version_number:2,content_hash:'b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3',author:{full_name:'Marcus Webb'},saved_at:'2024-11-03T14:00:00Z',change_summary:'Added browser history section',is_court_ready:false},
      {version_number:3,content_hash:'c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4',author:{full_name:'Diana Osei'},saved_at:'2024-11-04T10:00:00Z',change_summary:'Court-ready lock by legal reviewer',is_court_ready:true,locked_by:'Diana Osei',locked_at:'2024-11-04T10:00:00Z',review_notes:'All findings verified. Approved for court submission.'},
    ],
    r2:[
      {version_number:1,content_hash:'d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5',author:{full_name:'Marcus Webb'},saved_at:'2024-11-04T11:00:00Z',change_summary:'Initial version',is_court_ready:false},
    ],
  },
  users:[
    {id:'u1',email:'admin@forensics.local',full_name:'System Admin',role:'Admin',is_active:true,created_at:'2024-01-01T00:00:00Z'},
    {id:'u5',email:'james.park@forensics.local',full_name:'James Park',role:'CaseManager',is_active:true,created_at:'2024-06-01T00:00:00Z'},
    {id:'u2',email:'sarah.chen@forensics.local',full_name:'Sarah Chen',role:'LabTechnician',is_active:true,created_at:'2024-06-15T00:00:00Z'},
    {id:'u3',email:'marcus.webb@forensics.local',full_name:'Marcus Webb',role:'Examiner',is_active:true,created_at:'2024-06-15T00:00:00Z'},
    {id:'u4',email:'diana.osei@forensics.local',full_name:'Diana Osei',role:'LegalReviewer',is_active:true,created_at:'2024-07-01T00:00:00Z'},
  ],
  audit:[
    {id:'a1',action_type:'evidence.uploaded',actor_role:'LabTechnician',actor_id:'u2',resource_type:'evidence',resource_id:'e1',ip_address:'192.168.1.42',result:'success',timestamp:'2024-11-01T10:05:00Z',detail:{filename:'disk_image_workstation.dd',sha256:'3a7bd3e…',size_bytes:2147483648}},
    {id:'a2',action_type:'custody.transfer_initiated',actor_role:'LabTechnician',actor_id:'u2',resource_type:'custody_record',resource_id:'t1',ip_address:'192.168.1.42',result:'success',timestamp:'2024-11-01T10:30:00Z',detail:{evidence_id:'e1',to_user_id:'u3'}},
    {id:'a3',action_type:'custody.transfer_accepted',actor_role:'Examiner',actor_id:'u3',resource_type:'custody_record',resource_id:'t1',ip_address:'192.168.1.55',result:'success',timestamp:'2024-11-01T10:35:00Z',detail:{evidence_id:'e1'}},
    {id:'a4',action_type:'evidence.accessed',actor_role:'Examiner',actor_id:'u3',resource_type:'evidence',resource_id:'e1',ip_address:'192.168.1.55',result:'success',timestamp:'2024-11-02T09:00:00Z',detail:{integrity_match:true}},
    {id:'a5',action_type:'evidence.tamper_detected',actor_role:'Examiner',actor_id:'u3',resource_type:'evidence',resource_id:'e3',ip_address:'192.168.1.55',result:'failure',timestamp:'2024-11-02T09:15:00Z',detail:{stored_hash:'a87ff679…',recomputed_hash:'XXXXXXXX…'}},
    {id:'a6',action_type:'finding.created',actor_role:'Examiner',actor_id:'u3',resource_type:'finding',resource_id:'f1',ip_address:'192.168.1.55',result:'success',timestamp:'2024-11-02T14:00:00Z',detail:{task_id:'tk1',evidence_id:'e1'}},
    {id:'a7',action_type:'report.created',actor_role:'Examiner',actor_id:'u3',resource_type:'report',resource_id:'r1',ip_address:'192.168.1.55',result:'success',timestamp:'2024-11-03T09:00:00Z',detail:{title:'Disk Image Analysis — WS-0042'}},
    {id:'a8',action_type:'report.locked',actor_role:'LegalReviewer',actor_id:'u4',resource_type:'report_version',resource_id:'r1-v3',ip_address:'192.168.1.88',result:'success',timestamp:'2024-11-04T10:00:00Z',detail:{version:3}},
    {id:'a9',action_type:'verify.hash_queried',actor_role:null,actor_id:null,resource_type:'evidence',resource_id:'3a7bd3e…',ip_address:'203.0.113.42',result:'success',timestamp:'2024-11-05T08:30:00Z',detail:{found:true}},
    {id:'a10',action_type:'custody.transfer_initiated',actor_role:'Examiner',actor_id:'u3',resource_type:'custody_record',resource_id:'t2',ip_address:'192.168.1.55',result:'success',timestamp:'2024-11-04T14:00:00Z',detail:{evidence_id:'e1',to_user_id:'u4'}},
  ],
};

/* ── Helpers ────────────────────────────────────────────── */
const fmt=(iso)=>iso?new Date(iso).toLocaleString('en-GB',{day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit'}):'—';
const fmtDate=(iso)=>iso?new Date(iso).toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'}):'—';
const fmtSz=(b)=>{if(!b)return'—';if(b>=1e9)return(b/1e9).toFixed(1)+' GB';if(b>=1e6)return(b/1e6).toFixed(1)+' MB';return(b/1e3).toFixed(0)+' KB'};
const trunc=(h,s=10,e=8)=>h?`${h.slice(0,s)}…${h.slice(-e)}`:'—';

const Ico=({n,s=15})=>{
  const d={
    home:<><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></>,
    cases:<><rect x="2" y="3" width="20" height="18" rx="2"/><path d="M2 9h20M9 21V9"/></>,
    evidence:<><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></>,
    custody:<><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></>,
    tasks:<><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></>,
    reports:<><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><line x1="10" y1="9" x2="8" y2="9"/></>,
    verify:<><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></>,
    users:<><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></>,
    audit:<><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></>,
    plus:<><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></>,
    upload:<><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></>,
    download:<><polyline points="8 17 12 21 16 17"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.88 18.09A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.29"/></>,
    x:<><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></>,
    check:<><polyline points="20 6 9 17 4 12"/></>,
    alert:<><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></>,
    lock:<><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></>,
    link:<><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></>,
    arrow:<><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></>,
    eye:<><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></>,
    file:<><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></>,
    shield:<><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></>,
    filter:<><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></>,
    copy:<><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></>,
  };
  return <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">{d[n]||null}</svg>;
};

const Bdg=({s})=>{
  const map={verified:['b-verified','d-verified'],tampered:['b-tampered','d-tampered'],pending:['b-pending','d-pending'],unknown:['b-pending','d-pending'],open:['b-open',''],active:['b-active','d-verified'],closed:['b-closed',''],archived:['b-archived',''],court_ready:['b-court_ready',''],draft:['b-draft',''],under_review:['b-under_review','d-pending'],assigned:['b-assigned','d-pending'],in_progress:['b-in_progress',''],completed:['b-completed','d-verified'],reviewed:['b-reviewed',''],accepted:['b-accepted','d-verified'],rejected:['b-rejected','d-tampered'],imported:['b-draft',''],computed:['b-open','']};
  const[b,d]=map[s]||['b-draft',''];
  return <span className={`badge ${b}`}>{d&&<span className={`dot ${d}`}/>}{String(s).replace(/_/g,' ')}</span>;
};

const Modal=({title,onClose,children,footer,wide})=>(
  <div className="modal-bg" onClick={e=>e.target===e.currentTarget&&onClose()}>
    <div className="modal" style={wide?{maxWidth:600}:{}}>
      <div className="modal-hd">
        <span className="modal-title">{title}</span>
        <button className="modal-x" onClick={onClose}><Ico n="x" s={13}/></button>
      </div>
      <div className="modal-bd">{children}</div>
      {footer&&<div className="modal-ft">{footer}</div>}
    </div>
  </div>
);

/* ════════════ SCREENS ═════════════════════════════════════ */

/* ── Login ──────────────────────────────────────────────── */
function Login({onLogin}){
  const [role,setRole]=useState('CaseManager');
  const [email,setEmail]=useState('james.park@forensics.local');
  const [pass,setPass]=useState('');
  const roles=['CaseManager','LabTechnician','Examiner','LegalReviewer','Admin'];
  const handle=async e=>{
    e.preventDefault();
    try{const d=await api('/auth/login',{method:'POST',body:JSON.stringify({email,password:pass||'demo'})});onLogin({token:d.access_token,role,name:email.split('@')[0]});}
    catch{onLogin({token:'demo',role,name:email.split('@')[0]||'User'});}
  };
  return(
    <div className="login-wrap">
      <div className="login-box">
        <div style={{marginBottom:26}}>
          <div className="row" style={{gap:10,marginBottom:8}}>
            <div style={{width:34,height:34,borderRadius:8,background:'var(--blue)',display:'flex',alignItems:'center',justifyContent:'center'}}><Ico n="shield" s={17}/></div>
            <div><div style={{fontSize:15,fontWeight:600}}>ForensicChain</div><div style={{fontSize:11,color:'var(--text-3)'}}>Digital forensics case management</div></div>
          </div>
        </div>
        <div style={{fontSize:16,fontWeight:600,marginBottom:4}}>Sign in</div>
        <div style={{fontSize:12,color:'var(--text-3)',marginBottom:22}}>Choose a role to explore the interface</div>
        <form onSubmit={handle}>
          <div className="fgrp">
            <label className="flbl">Role (demo)</label>
            <div className="role-grid">
              {roles.map(r=><div key={r} className={`role-chip ${role===r?'sel':''}`} onClick={()=>setRole(r)}>{r.replace(/([A-Z])/g,' $1').trim()}</div>)}
            </div>
          </div>
          <div className="fgrp">
            <label className="flbl">Email</label>
            <input className="finp" value={email} onChange={e=>setEmail(e.target.value)} placeholder="user@forensics.local"/>
          </div>
          <div className="fgrp">
            <label className="flbl">Password</label>
            <input className="finp" type="password" value={pass} onChange={e=>setPass(e.target.value)} placeholder="Leave blank for demo"/>
          </div>
          <button type="submit" className="btn btn-primary" style={{width:'100%',justifyContent:'center',padding:'9px'}}>Sign in</button>
        </form>
        <div style={{marginTop:14,fontSize:11,color:'var(--text-4)',textAlign:'center'}}>Demo mode · no backend required · all data is local</div>
      </div>
    </div>
  );
}

/* ── Dashboard ──────────────────────────────────────────── */
function Dashboard({session,nav}){
  return(
    <div className="screen">
      <div className="stats">
        <div className="stat">
          <div className="stat-val">3</div>
          <div className="stat-lbl">Cases</div>
          <div className="stat-note">1 active · 1 open · 1 closed</div>
        </div>
        <div className="stat">
          <div className="stat-val">4</div>
          <div className="stat-lbl">Evidence items</div>
          <div className="stat-note">3 verified · 1 tampered</div>
        </div>
        <div className="stat">
          <div className="stat-val" style={{color:'var(--red)'}}>1</div>
          <div className="stat-lbl">Tamper alerts</div>
          <div className="stat-note">memory_dump_srv01.mem</div>
        </div>
        <div className="stat">
          <div className="stat-val">1</div>
          <div className="stat-lbl">Pending transfers</div>
          <div className="stat-note">Awaiting acceptance</div>
        </div>
      </div>

      <div className="g2" style={{gap:18}}>
        <div className="card">
          <div className="card-hd">
            <span className="card-title">Active cases</span>
            <button className="btn btn-ghost btn-sm" onClick={()=>nav('cases')}>View all</button>
          </div>
          <table className="tbl">
            <thead><tr><th>Case</th><th>Status</th><th>Evidence</th></tr></thead>
            <tbody>
              {M.cases.map(c=>(
                <tr key={c.id}>
                  <td>
                    <div className="tbl-link mono" style={{fontSize:12}} onClick={()=>nav('cases')}>{c.case_number}</div>
                    <div className="t3" style={{marginTop:2}}>{c.title}</div>
                  </td>
                  <td><Bdg s={c.status}/></td>
                  <td className="t3">{c.evidence_count} items</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="col">
          <div className="card">
            <div className="card-hd">
              <span className="card-title">Tamper alert</span>
              <span className="badge b-tampered"><span className="dot d-tampered"/>Critical</span>
            </div>
            <div className="card-bd">
              <div className="ibar bad" style={{marginBottom:14}}>
                <Ico n="alert" s={13}/>memory_dump_srv01.mem — hash mismatch
              </div>
              <div style={{marginBottom:10}}>
                <div className="t4" style={{marginBottom:4}}>Stored hash</div>
                <div className="hash-full" style={{fontSize:11}}>a87ff679a2f3e71d9181a67b7542122ceea7ec23a48eba7b4df679c9ca1a4f99</div>
              </div>
              <div style={{marginBottom:14}}>
                <div className="t4" style={{marginBottom:4}}>Recomputed</div>
                <div className="hash-full" style={{fontSize:11,color:'var(--red)',borderColor:'#FCA5A5'}}>XXXXXXXX00000000DEADBEEF00000000XXXXXXXX00000000DEADBEEF00000000</div>
              </div>
              <button className="btn btn-danger btn-sm" onClick={()=>nav('evidence')}><Ico n="eye" s={12}/>Review evidence</button>
            </div>
          </div>

          <div className="card">
            <div className="card-hd"><span className="card-title">Pending custody transfer</span></div>
            <div className="card-bd">
              <div style={{fontSize:13,fontWeight:500,marginBottom:6}}>disk_image_workstation.dd</div>
              <div className="t3" style={{marginBottom:10}}>Marcus Webb → Diana Osei (Legal Reviewer)</div>
              <div style={{marginBottom:12}}>
                <span className="hash" style={{maxWidth:'100%'}}>{trunc('3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b')}</span>
                <span className="t4" style={{marginLeft:6}}>hash at transfer</span>
              </div>
              {session.role==='LegalReviewer'&&<button className="btn btn-primary btn-sm"><Ico n="check" s={12}/>Accept custody</button>}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ── Cases ──────────────────────────────────────────────── */
function Cases({session}){
  const [cases,setCases]=useState(M.cases);
  const [sel,setSel]=useState(null);
  const [showNew,setShowNew]=useState(false);
  const [form,setForm]=useState({title:'',description:''});

  const create=()=>{
    const c={id:`c${Date.now()}`,case_number:`CASE-2024-00${150+cases.length}`,title:form.title,description:form.description,status:'open',created_at:new Date().toISOString(),evidence_count:0,assignment_count:0};
    setCases([c,...cases]);setForm({title:'',description:''});setShowNew(false);
  };

  if(sel) return(
    <div className="screen">
      <div className="detail-hd">
        <button className="back-btn" onClick={()=>setSel(null)}><Ico n="arrow" s={12}/>Cases</button>
        <span style={{color:'var(--text-3)',fontSize:13}}>/</span>
        <span className="mono" style={{fontSize:13,fontWeight:500}}>{sel.case_number}</span>
        <Bdg s={sel.status}/>
      </div>
      <div className="g2" style={{gap:18,marginBottom:18}}>
        <div className="card">
          <div className="card-hd"><span className="card-title">Case details</span></div>
          <div className="card-bd">
            <div style={{fontSize:16,fontWeight:600,marginBottom:8}}>{sel.title}</div>
            <div className="t3" style={{marginBottom:14,lineHeight:1.6}}>{sel.description}</div>
            <div className="g2" style={{gap:12}}>
              <div><div className="t4" style={{marginBottom:3}}>Case number</div><div className="mono" style={{fontSize:12}}>{sel.case_number}</div></div>
              <div><div className="t4" style={{marginBottom:3}}>Status</div><Bdg s={sel.status}/></div>
              <div><div className="t4" style={{marginBottom:3}}>Opened</div><div style={{fontSize:12}}>{fmtDate(sel.created_at)}</div></div>
              <div><div className="t4" style={{marginBottom:3}}>Evidence</div><div style={{fontSize:12}}>{sel.evidence_count} items</div></div>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="card-hd"><span className="card-title">Assigned personnel</span></div>
          <table className="tbl">
            <thead><tr><th>Name</th><th>Role</th><th>Assigned</th></tr></thead>
            <tbody>
              <tr><td><div style={{fontWeight:500}}>Sarah Chen</div></td><td><Bdg s="LabTechnician"/></td><td className="t3" style={{fontSize:11}}>{fmtDate('2024-11-01T00:00:00Z')}</td></tr>
              <tr><td><div style={{fontWeight:500}}>Marcus Webb</div></td><td><Bdg s="Examiner"/></td><td className="t3" style={{fontSize:11}}>{fmtDate('2024-11-01T00:00:00Z')}</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div className="card">
        <div className="card-hd"><span className="card-title">Evidence on this case</span></div>
        <table className="tbl">
          <thead><tr><th>Filename</th><th>SHA-256</th><th>Integrity</th><th>Custodian</th><th>Registered</th></tr></thead>
          <tbody>
            {M.evidence.map(e=>(
              <tr key={e.id}>
                <td><div style={{fontWeight:500}}>{e.filename}</div><div className="t4">{e.evidence_type?.replace(/_/g,' ')}</div></td>
                <td><span className="hash">{trunc(e.sha256_hash)}</span></td>
                <td><Bdg s={e.integrity_status}/></td>
                <td className="t3">{e.current_custodian_id==='u2'?'Sarah Chen':e.current_custodian_id==='u3'?'Marcus Webb':'Diana Osei'}</td>
                <td className="t3" style={{fontSize:11}}>{fmtDate(e.uploaded_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  return(
    <div className="screen">
      {showNew&&(
        <Modal title="Open new case" onClose={()=>setShowNew(false)} footer={<><button className="btn btn-ghost" onClick={()=>setShowNew(false)}>Cancel</button><button className="btn btn-primary" onClick={create} disabled={!form.title}>Open case</button></>}>
          <div className="fgrp"><label className="flbl">Case title</label><input className="finp" value={form.title} onChange={e=>setForm({...form,title:e.target.value})} placeholder="e.g. Insider Trading Investigation"/></div>
          <div className="fgrp"><label className="flbl">Description</label><textarea className="finp fta" value={form.description} onChange={e=>setForm({...form,description:e.target.value})} placeholder="Brief overview of the investigation..."/></div>
          <div className="fgrp"><label className="flbl">External reference (optional)</label><input className="finp" placeholder="Police incident number, court reference..."/></div>
        </Modal>
      )}
      <div className="rb" style={{marginBottom:18}}>
        <span className="t3">{cases.length} cases</span>
        {['CaseManager','Admin'].includes(session.role)&&<button className="btn btn-primary" onClick={()=>setShowNew(true)}><Ico n="plus" s={13}/>Open case</button>}
      </div>
      <div className="card">
        <table className="tbl">
          <thead><tr><th>Case number</th><th>Title</th><th>Status</th><th>Evidence</th><th>Opened</th><th/></tr></thead>
          <tbody>
            {cases.map(c=>(
              <tr key={c.id}>
                <td><span className="mono" style={{fontSize:12,fontWeight:500}}>{c.case_number}</span></td>
                <td><span className="tbl-link" onClick={()=>setSel(c)}>{c.title}</span></td>
                <td><Bdg s={c.status}/></td>
                <td className="t3">{c.evidence_count}</td>
                <td className="t3" style={{fontSize:11}}>{fmtDate(c.created_at)}</td>
                <td><button className="btn btn-ghost btn-sm" onClick={()=>setSel(c)}>Open</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ── Evidence ────────────────────────────────────────────── */
function Evidence({session}){
  const [ev,setEv]=useState(M.evidence);
  const [showUp,setShowUp]=useState(false);
  const [file,setFile]=useState(null);
  const [desc,setDesc]=useState('');
  const [uping,setUping]=useState(false);
  const [tab,setTab]=useState('upload');
  const [csvRows,setCsvRows]=useState(null);
  const [showHash,setShowHash]=useState(null);
  const fileRef=useRef();

  const doUpload=()=>{
    if(!file)return;
    setUping(true);
    setTimeout(()=>{
      const h=Array.from({length:64},()=>'0123456789abcdef'[Math.floor(Math.random()*16)]).join('');
      setEv([{id:`e${Date.now()}`,filename:file.name,evidence_type:'file',sha256_hash:h,integrity_status:'verified',uploaded_at:new Date().toISOString(),file_size_bytes:file.size,hash_source:'computed',description:desc,current_custodian_id:'u2'},...ev]);
      setUping(false);setShowUp(false);setFile(null);setDesc('');
    },1100);
  };

  const simCsv=()=>{ setCsvRows([{row:1,filename:'disk_sector_01.dd',sha256:'3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b',status:'imported'},{row:2,filename:'log_export.evtx',sha256:'8f14e45fceea167a5a36dedd4bea2543a18b8050b5d5b1be1e23e2b5b3ecf9d2',status:'imported'},{row:3,filename:'bad_row.bin',sha256:'NOTVALID',status:'error',message:'Invalid SHA-256 format'}]); };

  return(
    <div className="screen">
      {showHash&&(
        <Modal title="SHA-256 hash" onClose={()=>setShowHash(null)} footer={<button className="btn btn-ghost" onClick={()=>setShowHash(null)}>Close</button>}>
          <div className="fgrp"><label className="flbl">Filename</label><div style={{fontSize:13,fontWeight:500}}>{showHash.filename}</div></div>
          <div className="fgrp"><label className="flbl">Hash (SHA-256)</label><div className="hash-full">{showHash.sha256_hash}</div></div>
          <div className="fgrp"><label className="flbl">Source</label><Bdg s={showHash.hash_source}/></div>
          <div className="fgrp"><label className="flbl">Integrity status</label><Bdg s={showHash.integrity_status}/></div>
          {showHash.integrity_status==='tampered'&&<div className="alert a-danger"><Ico n="alert" s={13}/>This file's current hash does not match the stored hash. Access is restricted pending review.</div>}
        </Modal>
      )}
      {showUp&&(
        <Modal title="Register evidence" onClose={()=>setShowUp(false)} wide footer={tab==='upload'?<><button className="btn btn-ghost" onClick={()=>setShowUp(false)}>Cancel</button><button className="btn btn-primary" onClick={doUpload} disabled={!file||uping}>{uping?<span className="spin">◌</span>:null} {uping?'Computing hash…':'Register'}</button></>:<button className="btn btn-ghost" onClick={()=>setShowUp(false)}>Done</button>}>
          <div className="alert a-info"><Ico n="shield" s={13}/>SHA-256 is always computed server-side. The hash you see in results is never taken from the client.</div>
          <div className="tabs">
            <button className={`tab ${tab==='upload'?'on':''}`} onClick={()=>setTab('upload')}>Upload file</button>
            <button className={`tab ${tab==='import'?'on':''}`} onClick={()=>setTab('import')}>Import from Autopsy / FTK</button>
          </div>
          {tab==='upload'?(
            <>
              <input ref={fileRef} type="file" style={{display:'none'}} onChange={e=>setFile(e.target.files[0])}/>
              <div className="dropzone" onClick={()=>fileRef.current.click()} onDragOver={e=>e.preventDefault()} onDrop={e=>{e.preventDefault();setFile(e.dataTransfer.files[0]);}}>
                <div className="dz-icon">📁</div>
                {file?<><div className="dz-text">{file.name}</div><div className="dz-sub">{fmtSz(file.size)}</div></>:<><div className="dz-text">Drop file here, or click to browse</div><div className="dz-sub">Any file type · Max 2 GB · Hash computed automatically</div></>}
              </div>
              <div className="fgrp" style={{marginTop:14}}>
                <label className="flbl">Evidence type</label>
                <select className="finp fsel"><option>file</option><option>disk_image</option><option>memory_dump</option><option>network_capture</option><option>log_file</option><option>mobile_backup</option></select>
              </div>
              <div className="fgrp">
                <label className="flbl">Description</label>
                <textarea className="finp fta" value={desc} onChange={e=>setDesc(e.target.value)} placeholder="Where was this acquired? What does it contain?"/>
              </div>
            </>
          ):(
            <>
              <div className="fgrp"><label className="flbl">Forensic tool</label><input className="finp" placeholder="e.g. Autopsy 4.20, FTK 7.1"/></div>
              <div className="dropzone" onClick={simCsv}>
                <div className="dz-icon">📋</div>
                <div className="dz-text">Upload CSV or JSON hash export</div>
                <div className="dz-sub">Required columns: filename, sha256, acquisition_tool, acquisition_date</div>
              </div>
              {csvRows&&(
                <div style={{marginTop:14}}>
                  <div className="rb" style={{marginBottom:8}}>
                    <div className="row"><span style={{fontSize:12,color:'var(--green)',fontWeight:500}}>✓ {csvRows.filter(r=>r.status==='imported').length} imported</span><span style={{fontSize:12,color:'var(--red)',fontWeight:500}}>✗ {csvRows.filter(r=>r.status==='error').length} errors</span></div>
                  </div>
                  {csvRows.map(r=>(
                    <div key={r.row} style={{fontSize:12,padding:'6px 0',borderBottom:'1px solid var(--border)',display:'flex',gap:8,alignItems:'flex-start'}}>
                      <span style={{color:r.status==='error'?'var(--red)':'var(--green)',fontWeight:600,flexShrink:0}}>{r.status==='error'?'✗':'✓'}</span>
                      <div>
                        <div style={{fontWeight:500}}>{r.filename}</div>
                        {r.sha256&&<div className="hash" style={{maxWidth:240}}>{trunc(r.sha256)}</div>}
                        {r.message&&<div style={{color:'var(--red)',marginTop:2}}>{r.message}</div>}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </Modal>
      )}

      <div className="rb" style={{marginBottom:18}}>
        <div className="row">
          <span className="t3">{ev.length} items · CASE-2024-00142</span>
          <span className="badge b-tampered"><span className="dot d-tampered"/>1 tampered</span>
        </div>
        {session.role==='LabTechnician'&&<button className="btn btn-primary" onClick={()=>setShowUp(true)}><Ico n="upload" s={13}/>Register evidence</button>}
      </div>

      <div className="card">
        <table className="tbl">
          <thead><tr><th>Filename</th><th>SHA-256</th><th>Type</th><th>Size</th><th>Source</th><th>Integrity</th><th>Registered</th><th/></tr></thead>
          <tbody>
            {ev.map(e=>(
              <tr key={e.id} style={e.integrity_status==='tampered'?{background:'#FEF2F2'}:{}}>
                <td><div style={{fontWeight:500}}>{e.filename}</div><div className="t4">{e.description}</div></td>
                <td><span className="hash" style={{cursor:'pointer'}} onClick={()=>setShowHash(e)}>{trunc(e.sha256_hash)}</span></td>
                <td className="t3">{e.evidence_type?.replace(/_/g,' ')}</td>
                <td className="t3">{fmtSz(e.file_size_bytes)}</td>
                <td><Bdg s={e.hash_source}/></td>
                <td><Bdg s={e.integrity_status}/></td>
                <td className="t3" style={{fontSize:11}}>{fmtDate(e.uploaded_at)}</td>
                <td>
                  <div className="row" style={{gap:4}}>
                    <button className="btn-icon" onClick={()=>setShowHash(e)} title="View hash"><Ico n="eye" s={12}/></button>
                    {e.integrity_status!=='tampered'&&<button className="btn-icon" title="Download"><Ico n="download" s={12}/></button>}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ── Custody ─────────────────────────────────────────────── */
function Custody({session}){
  const [transfers,setTransfers]=useState(M.custody);
  const [showTx,setShowTx]=useState(false);
  const [reason,setReason]=useState('');

  const accept=id=>setTransfers(ts=>ts.map(t=>t.id===id?{...t,status:'accepted',accepted_at:new Date().toISOString()}:t));

  return(
    <div className="screen">
      {showTx&&(
        <Modal title="Initiate custody transfer" onClose={()=>setShowTx(false)} footer={<><button className="btn btn-ghost" onClick={()=>setShowTx(false)}>Cancel</button><button className="btn btn-primary" onClick={()=>{setTransfers([{id:`t${Date.now()}`,evidence_id:'e1',from_user:{id:'u3',full_name:'Marcus Webb',role:'Examiner'},to_user:{id:'u4',full_name:'Diana Osei',role:'LegalReviewer'},transfer_reason:reason,hash_at_transfer:'3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b',status:'pending',initiated_at:new Date().toISOString(),accepted_at:null},...transfers]);setShowTx(false);setReason('');}}>Initiate transfer</button></>}>
          <div className="alert a-warn"><Ico n="alert" s={13}/>The evidence hash will be re-verified before transfer. A mismatch will block this action.</div>
          <div className="fgrp">
            <label className="flbl">Evidence item</label>
            <select className="finp fsel">{M.evidence.filter(e=>e.integrity_status!=='tampered').map(e=><option key={e.id}>{e.filename}</option>)}</select>
          </div>
          <div className="fgrp">
            <label className="flbl">Transfer to</label>
            <select className="finp fsel"><option>Diana Osei (Legal Reviewer)</option><option>Sarah Chen (Lab Technician)</option></select>
          </div>
          <div className="fgrp">
            <label className="flbl">Reason for transfer</label>
            <textarea className="finp fta" value={reason} onChange={e=>setReason(e.target.value)} placeholder="Explain why custody is being transferred..."/>
          </div>
        </Modal>
      )}

      <div className="rb" style={{marginBottom:18}}>
        <div className="row">
          <span className="t3">{transfers.length} custody records · CASE-2024-00142</span>
          {transfers.some(t=>t.status==='pending')&&<span className="badge b-pending"><span className="dot d-pending"/>{transfers.filter(t=>t.status==='pending').length} pending</span>}
        </div>
        {['LabTechnician','Examiner'].includes(session.role)&&<button className="btn btn-primary" onClick={()=>setShowTx(true)}><Ico n="link" s={13}/>Transfer custody</button>}
      </div>

      <div className="g2" style={{gap:18}}>
        <div className="card">
          <div className="card-hd"><span className="card-title">Custody timeline — disk_image_workstation.dd</span></div>
          <div className="card-bd">
            {transfers.every(t=>t.status==='accepted')
              ?<div className="ibar ok" style={{marginBottom:18}}><Ico n="shield" s={13}/>Chain complete · No gaps detected</div>
              :<div className="ibar warn" style={{marginBottom:18}}><Ico n="alert" s={13}/>Pending transfer — chain not yet closed</div>
            }
            <div className="timeline">
              {[...transfers].reverse().map(t=>(
                <div className="tl-item" key={t.id}>
                  <div className={`tl-dot ${t.status}`}/>
                  <div className="tl-when">{fmt(t.initiated_at)}</div>
                  <div className="tl-who">{t.from_user.full_name} <span style={{color:'var(--text-3)',fontWeight:400}}>→</span> {t.to_user.full_name}</div>
                  <div className="tl-detail" style={{marginBottom:6}}>{t.transfer_reason}</div>
                  <div className="row" style={{flexWrap:'wrap',gap:6,marginBottom:t.status==='pending'&&session.role==='LegalReviewer'?8:0}}>
                    <Bdg s={t.status}/>
                    {t.accepted_at&&<span className="t4">accepted {fmt(t.accepted_at)}</span>}
                    <span className="hash">{trunc(t.hash_at_transfer)}</span>
                  </div>
                  {t.status==='pending'&&session.role==='LegalReviewer'&&(
                    <div className="row" style={{marginTop:6,gap:6}}>
                      <button className="btn btn-primary btn-sm" onClick={()=>accept(t.id)}><Ico n="check" s={12}/>Accept</button>
                      <button className="btn btn-ghost btn-sm"><Ico n="x" s={12}/>Reject</button>
                    </div>
                  )}
                  {t.status==='pending'&&session.role==='Examiner'&&<div className="t4" style={{marginTop:4}}>Awaiting acceptance from {t.to_user.full_name}</div>}
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-hd"><span className="card-title">All transfers</span></div>
          <table className="tbl">
            <thead><tr><th>Evidence</th><th>From → To</th><th>Status</th><th>Initiated</th></tr></thead>
            <tbody>
              {[...transfers].reverse().map(t=>(
                <tr key={t.id}>
                  <td style={{fontSize:11}} className="mono">disk_image…dd</td>
                  <td><div style={{fontSize:12,fontWeight:500}}>{t.from_user.full_name}</div><div className="t4">→ {t.to_user.full_name}</div></td>
                  <td><Bdg s={t.status}/></td>
                  <td className="t3" style={{fontSize:11}}>{fmtDate(t.initiated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

/* ── Tasks ───────────────────────────────────────────────── */
function Tasks({session}){
  const [tasks,setTasks]=useState(M.tasks);
  const [findings,setFindings]=useState(M.findings);
  const [sel,setSel]=useState(null);
  const [showNew,setShowNew]=useState(false);
  const [showFinding,setShowFinding]=useState(false);
  const [fForm,setFForm]=useState({title:'',content:''});
  const [tForm,setTForm]=useState({title:'',description:'',due_date:''});

  const advance=id=>setTasks(ts=>ts.map(t=>{
    if(t.id!==id)return t;
    const next={assigned:'in_progress',in_progress:'completed',completed:'reviewed'}[t.status]||t.status;
    return {...t,status:next};
  }));

  const addFinding=()=>{
    const f={id:`f${Date.now()}`,task_id:sel.id,evidence_id:sel.evidence_ids[0],title:fForm.title,content:fForm.content,attachments:[],created_by:{full_name:session.name},created_at:new Date().toISOString()};
    setFindings([...findings,f]);
    setTasks(ts=>ts.map(t=>t.id===sel.id?{...t,findings_count:(t.findings_count||0)+1}:t));
    setFForm({title:'',content:''});setShowFinding(false);
  };

  const createTask=()=>{
    const t={id:`tk${Date.now()}`,title:tForm.title,description:tForm.description,status:'assigned',assigned_to:{full_name:'Marcus Webb'},assigned_by:{full_name:session.name},due_date:tForm.due_date||null,evidence_ids:['e1'],created_at:new Date().toISOString(),findings_count:0};
    setTasks([...tasks,t]);setTForm({title:'',description:'',due_date:''});setShowNew(false);
  };

  const taskFindings=sel?findings.filter(f=>f.task_id===sel.id):[];

  if(sel) return(
    <div className="screen">
      {showFinding&&(
        <Modal title="Record finding" onClose={()=>setShowFinding(false)} footer={<><button className="btn btn-ghost" onClick={()=>setShowFinding(false)}>Cancel</button><button className="btn btn-primary" onClick={addFinding} disabled={!fForm.title||!fForm.content}>Save finding</button></>}>
          <div className="fgrp"><label className="flbl">Finding title</label><input className="finp" value={fForm.title} onChange={e=>setFForm({...fForm,title:e.target.value})} placeholder="Brief title for this finding"/></div>
          <div className="fgrp"><label className="flbl">Detail (Markdown supported)</label><textarea className="finp fta" style={{minHeight:140}} value={fForm.content} onChange={e=>setFForm({...fForm,content:e.target.value})} placeholder="Describe what you found, how you found it, and why it is significant..."/></div>
          <div className="fgrp"><label className="flbl">Evidence item</label><select className="finp fsel">{M.evidence.map(e=><option key={e.id}>{e.filename}</option>)}</select></div>
        </Modal>
      )}
      <div className="detail-hd">
        <button className="back-btn" onClick={()=>setSel(null)}><Ico n="arrow" s={12}/>Tasks</button>
        <span style={{color:'var(--text-3)',fontSize:13}}>/</span>
        <span style={{fontSize:13,fontWeight:500}}>{sel.title}</span>
        <Bdg s={sel.status}/>
      </div>
      <div className="g2" style={{gap:18,marginBottom:18}}>
        <div className="card">
          <div className="card-hd"><span className="card-title">Task details</span></div>
          <div className="card-bd">
            <div className="g2" style={{gap:12}}>
              <div><div className="t4" style={{marginBottom:3}}>Assigned to</div><div style={{fontSize:13,fontWeight:500}}>{sel.assigned_to.full_name}</div></div>
              <div><div className="t4" style={{marginBottom:3}}>Assigned by</div><div style={{fontSize:13}}>{sel.assigned_by.full_name}</div></div>
              <div><div className="t4" style={{marginBottom:3}}>Due date</div><div style={{fontSize:13}}>{sel.due_date?fmtDate(sel.due_date):'—'}</div></div>
              <div><div className="t4" style={{marginBottom:3}}>Created</div><div style={{fontSize:13}}>{fmtDate(sel.created_at)}</div></div>
            </div>
            <div className="divider"/>
            <div className="t4" style={{marginBottom:6}}>Linked evidence</div>
            {M.evidence.filter(e=>sel.evidence_ids.includes(e.id)).map(e=>(
              <div key={e.id} className="row" style={{gap:8,padding:'6px 0',borderBottom:'1px solid var(--border)'}}>
                <Ico n="file" s={13}/>
                <span style={{fontSize:12,fontWeight:500}}>{e.filename}</span>
                <Bdg s={e.integrity_status}/>
              </div>
            ))}
          </div>
        </div>
        <div className="card">
          <div className="card-hd"><span className="card-title">Status</span></div>
          <div className="card-bd">
            <div style={{marginBottom:16}}>
              {['assigned','in_progress','completed','reviewed'].map((s,i)=>(
                <div key={s} className="row" style={{gap:8,padding:'8px 0',borderBottom:i<3?'1px solid var(--border)':'none'}}>
                  <div style={{width:10,height:10,borderRadius:'50%',background:sel.status===s?'var(--blue)':['assigned','in_progress','completed','reviewed'].indexOf(sel.status)>i?'var(--green)':'var(--border)',flexShrink:0}}/>
                  <span style={{fontSize:13,fontWeight:sel.status===s?500:400,color:sel.status===s?'var(--text)':'var(--text-3)'}}>{s.replace(/_/g,' ')}</span>
                  {sel.status===s&&<span className="badge b-open" style={{marginLeft:'auto',fontSize:10}}>current</span>}
                </div>
              ))}
            </div>
            {session.role==='Examiner'&&sel.status!=='reviewed'&&(
              <button className="btn btn-primary btn-sm" onClick={()=>{ advance(sel.id); setSel(t=>({...t,status:{assigned:'in_progress',in_progress:'completed',completed:'reviewed'}[t.status]||t.status})); }}>
                Advance to {({assigned:'In progress',in_progress:'Completed',completed:'Reviewed'})[sel.status]}
              </button>
            )}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-hd">
          <span className="card-title">Findings ({taskFindings.length})</span>
          {session.role==='Examiner'&&<button className="btn btn-primary btn-sm" onClick={()=>setShowFinding(true)}><Ico n="plus" s={12}/>Add finding</button>}
        </div>
        {taskFindings.length===0?(
          <div className="empty"><div className="empty-icon">📋</div>No findings recorded yet{session.role==='Examiner'&&' — add your first finding above'}</div>
        ):(
          <div style={{padding:'0 18px 18px'}}>
            {taskFindings.map((f,i)=>(
              <div key={f.id} style={{padding:'16px 0',borderBottom:i<taskFindings.length-1?'1px solid var(--border)':'none'}}>
                <div className="rb" style={{marginBottom:6}}>
                  <div style={{fontSize:13,fontWeight:600}}>{f.title}</div>
                  <span className="t4">{fmt(f.created_at)}</span>
                </div>
                <div style={{fontSize:13,color:'var(--text-2)',lineHeight:1.7,marginBottom:6}}>{f.content}</div>
                <div className="row"><div className="avatar" style={{width:20,height:20,fontSize:9}}>{f.created_by.full_name.split(' ').map(n=>n[0]).join('')}</div><span className="t3">{f.created_by.full_name}</span></div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );

  return(
    <div className="screen">
      {showNew&&(
        <Modal title="Assign task" onClose={()=>setShowNew(false)} footer={<><button className="btn btn-ghost" onClick={()=>setShowNew(false)}>Cancel</button><button className="btn btn-primary" onClick={createTask} disabled={!tForm.title}>Assign task</button></>}>
          <div className="fgrp"><label className="flbl">Task title</label><input className="finp" value={tForm.title} onChange={e=>setTForm({...tForm,title:e.target.value})} placeholder="e.g. Recover deleted files from disk image"/></div>
          <div className="fgrp"><label className="flbl">Description</label><textarea className="finp fta" value={tForm.description} onChange={e=>setTForm({...tForm,description:e.target.value})} placeholder="What should the examiner do?"/></div>
          <div className="fgrp"><label className="flbl">Assign to</label><select className="finp fsel"><option>Marcus Webb (Examiner)</option></select></div>
          <div className="fgrp"><label className="flbl">Evidence items</label><select className="finp fsel">{M.evidence.map(e=><option key={e.id}>{e.filename}</option>)}</select></div>
          <div className="fgrp"><label className="flbl">Due date (optional)</label><input className="finp" type="date" value={tForm.due_date} onChange={e=>setTForm({...tForm,due_date:e.target.value})}/></div>
        </Modal>
      )}
      <div className="rb" style={{marginBottom:18}}>
        <span className="t3">{tasks.length} tasks · CASE-2024-00142</span>
        {session.role==='CaseManager'&&<button className="btn btn-primary" onClick={()=>setShowNew(true)}><Ico n="plus" s={13}/>Assign task</button>}
      </div>
      <div className="card">
        <table className="tbl">
          <thead><tr><th>Task</th><th>Assigned to</th><th>Evidence</th><th>Findings</th><th>Status</th><th>Due</th><th/></tr></thead>
          <tbody>
            {tasks.map(t=>(
              <tr key={t.id}>
                <td><span className="tbl-link" onClick={()=>setSel(t)}>{t.title}</span></td>
                <td className="t3">{t.assigned_to.full_name}</td>
                <td>{t.evidence_ids.map(id=>{const e=M.evidence.find(x=>x.id===id);return e?<span key={id} className="tag" style={{fontSize:10}}>{e.filename.slice(0,20)}…</span>:null})}</td>
                <td className="t3">{t.findings_count}</td>
                <td><Bdg s={t.status}/></td>
                <td className="t3" style={{fontSize:11}}>{t.due_date?fmtDate(t.due_date):'—'}</td>
                <td><button className="btn btn-ghost btn-sm" onClick={()=>setSel(t)}>Open</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ── Reports ─────────────────────────────────────────────── */
function Reports({session}){
  const [reports,setReports]=useState(M.reports);
  const [versions,setVersions]=useState(M.report_versions);
  const [sel,setSel]=useState(null);
  const [vtab,setVtab]=useState('versions');
  const [draftContent,setDraftContent]=useState('');
  const [changeSummary,setChangeSummary]=useState('');
  const [showNew,setShowNew]=useState(false);
  const [newTitle,setNewTitle]=useState('');

  const saveVersion=()=>{
    const v={version_number:sel.latest_version+1,content_hash:Array.from({length:64},()=>'0123456789abcdef'[Math.floor(Math.random()*16)]).join(''),author:{full_name:session.name},saved_at:new Date().toISOString(),change_summary:changeSummary,is_court_ready:false};
    setVersions(vs=>({...vs,[sel.id]:[...(vs[sel.id]||[]),v]}));
    setReports(rs=>rs.map(r=>r.id===sel.id?{...r,latest_version:r.latest_version+1}:r));
    setSel(r=>({...r,latest_version:r.latest_version+1}));
    setChangeSummary('');
  };

  const lockReport=()=>{
    const v=sel.latest_version;
    setVersions(vs=>({...vs,[sel.id]:(vs[sel.id]||[]).map(vr=>vr.version_number===v?{...vr,is_court_ready:true,locked_by:session.name,locked_at:new Date().toISOString(),review_notes:'Approved for court submission.'}:vr)}));
    setReports(rs=>rs.map(r=>r.id===sel.id?{...r,status:'court_ready',court_ready_version:v}:r));
    setSel(r=>({...r,status:'court_ready',court_ready_version:v}));
  };

  const createReport=()=>{
    const r={id:`r${Date.now()}`,title:newTitle,status:'draft',latest_version:1,court_ready_version:null,created_at:new Date().toISOString(),created_by:session.name};
    const v={version_number:1,content_hash:Array.from({length:64},()=>'0123456789abcdef'[Math.floor(Math.random()*16)]).join(''),author:{full_name:session.name},saved_at:new Date().toISOString(),change_summary:'Initial version',is_court_ready:false};
    setReports([...reports,r]);setVersions(vs=>({...vs,[r.id]:[v]}));setNewTitle('');setShowNew(false);
  };

  const curVersions=sel?(versions[sel.id]||[]):[];
  const isLocked=sel&&sel.status==='court_ready';

  if(sel) return(
    <div className="screen">
      <div className="detail-hd">
        <button className="back-btn" onClick={()=>setSel(null)}><Ico n="arrow" s={12}/>Reports</button>
        <span style={{color:'var(--text-3)',fontSize:13}}>/</span>
        <span style={{fontSize:13,fontWeight:500,maxWidth:300,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{sel.title}</span>
        <Bdg s={sel.status}/>
        <div style={{marginLeft:'auto',display:'flex',gap:8}}>
          {!isLocked&&session.role==='LegalReviewer'&&<button className="btn btn-primary btn-sm" onClick={lockReport}><Ico n="lock" s={12}/>Lock as court-ready</button>}
          {isLocked&&<button className="btn btn-ghost btn-sm"><Ico n="download" s={12}/>Download PDF</button>}
        </div>
      </div>

      {isLocked&&<div className="alert a-warn" style={{marginBottom:18}}><Ico n="lock" s={13}/>Version {sel.court_ready_version} is court-ready locked. New edits must start a new draft cycle.</div>}

      <div className="tabs">
        <button className={`tab ${vtab==='versions'?'on':''}`} onClick={()=>setVtab('versions')}>Version history</button>
        {!isLocked&&session.role==='Examiner'&&<button className={`tab ${vtab==='edit'?'on':''}`} onClick={()=>setVtab('edit')}>Edit draft</button>}
      </div>

      {vtab==='versions'&&(
        <div className="card">
          <table className="tbl">
            <thead><tr><th>Version</th><th>Content hash</th><th>Author</th><th>Saved</th><th>Change summary</th><th/></tr></thead>
            <tbody>
              {[...curVersions].reverse().map(v=>(
                <tr key={v.version_number}>
                  <td>
                    <span style={{fontWeight:600}}>v{v.version_number}</span>
                    {v.is_court_ready&&<span style={{marginLeft:8}}><Bdg s="court_ready"/></span>}
                    {v.version_number===sel.latest_version&&!v.is_court_ready&&<span className="tag" style={{marginLeft:6,fontSize:10}}>latest</span>}
                  </td>
                  <td><span className="hash">{trunc(v.content_hash)}</span></td>
                  <td className="t3">{v.author.full_name}</td>
                  <td className="t3" style={{fontSize:11}}>{fmt(v.saved_at)}</td>
                  <td className="t3">{v.change_summary}</td>
                  <td><button className="btn btn-ghost btn-sm">View</button></td>
                </tr>
              ))}
            </tbody>
          </table>
          {curVersions.some(v=>v.is_court_ready)&&(
            <div style={{padding:'14px 18px',borderTop:'1px solid var(--border)',background:'#FFFBEB'}}>
              <div style={{fontSize:12,color:'var(--amber)',fontWeight:500,marginBottom:4}}>Review notes — v{sel.court_ready_version}</div>
              <div style={{fontSize:12,color:'var(--text-2)'}}>{curVersions.find(v=>v.is_court_ready)?.review_notes}</div>
              <div style={{fontSize:11,color:'var(--text-3)',marginTop:4}}>Locked by {curVersions.find(v=>v.is_court_ready)?.locked_by} · {fmt(curVersions.find(v=>v.is_court_ready)?.locked_at)}</div>
            </div>
          )}
        </div>
      )}

      {vtab==='edit'&&(
        <div className="card">
          <div className="card-bd">
            <div className="fgrp">
              <label className="flbl">Report content (Markdown)</label>
              <textarea className="finp fta" style={{minHeight:320,fontFamily:'JetBrains Mono',fontSize:12,lineHeight:1.7}} value={draftContent} onChange={e=>setDraftContent(e.target.value)} placeholder={'# Forensic Report\n\n## Summary\n\n## Evidence analysed\n\n## Findings\n\n## Conclusion\n'}/>
            </div>
            <div className="fgrp">
              <label className="flbl">Change summary</label>
              <input className="finp" value={changeSummary} onChange={e=>setChangeSummary(e.target.value)} placeholder="What changed in this version?"/>
            </div>
            <div className="row">
              <button className="btn btn-primary" onClick={saveVersion} disabled={!changeSummary}>Save as version {sel.latest_version+1}</button>
              <span className="t3">Content hash will be computed server-side on save</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );

  return(
    <div className="screen">
      {showNew&&(
        <Modal title="Create report" onClose={()=>setShowNew(false)} footer={<><button className="btn btn-ghost" onClick={()=>setShowNew(false)}>Cancel</button><button className="btn btn-primary" onClick={createReport} disabled={!newTitle}>Create</button></>}>
          <div className="fgrp"><label className="flbl">Report title</label><input className="finp" value={newTitle} onChange={e=>setNewTitle(e.target.value)} placeholder="e.g. Disk Image Analysis — WS-0042"/></div>
        </Modal>
      )}
      <div className="rb" style={{marginBottom:18}}>
        <span className="t3">{reports.length} reports · CASE-2024-00142</span>
        {session.role==='Examiner'&&<button className="btn btn-primary" onClick={()=>setShowNew(true)}><Ico n="plus" s={13}/>New report</button>}
      </div>
      <div className="card">
        <table className="tbl">
          <thead><tr><th>Title</th><th>Status</th><th>Latest version</th><th>Court-ready</th><th>Author</th><th>Created</th><th/></tr></thead>
          <tbody>
            {reports.map(r=>(
              <tr key={r.id}>
                <td><span className="tbl-link" onClick={()=>setSel(r)}>{r.title}</span></td>
                <td><Bdg s={r.status}/></td>
                <td className="t3">v{r.latest_version}</td>
                <td>{r.court_ready_version?<span className="badge b-court_ready"><Ico n="lock" s={10}/>v{r.court_ready_version}</span>:<span className="t3">—</span>}</td>
                <td className="t3">{r.created_by}</td>
                <td className="t3" style={{fontSize:11}}>{fmtDate(r.created_at)}</td>
                <td><button className="btn btn-ghost btn-sm" onClick={()=>setSel(r)}>Open</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ── Verify ──────────────────────────────────────────────── */
function Verify(){
  const [h,setH]=useState('');
  const [res,setRes]=useState(null);
  const [loading,setLoading]=useState(false);
  const [copied,setCopied]=useState(false);

  const check=async()=>{
    if(h.length!==64)return;
    setLoading(true);setRes(null);
    try{const d=await api(`/verify/${h}`);setRes(d);}
    catch{
      await new Promise(r=>setTimeout(r,700));
      const found=M.evidence.find(e=>e.sha256_hash===h);
      setRes(found?{hash:h,status:found.integrity_status,first_registered_at:found.uploaded_at,custody_transfer_count:M.custody.filter(t=>t.evidence_id===found.id).length,case_number:null,report_versions_count:1,verified_at:new Date().toISOString()}:{hash:h,status:'not_found',verified_at:new Date().toISOString()});
    }
    setLoading(false);
  };

  const copy=text=>{navigator.clipboard?.writeText(text);setCopied(true);setTimeout(()=>setCopied(false),1500);};
  const validFmt=h.length===64&&/^[a-f0-9]+$/.test(h);
  const resClass=res?res.status==='verified'?'ok':res.status==='not_found'?'none':'bad':'';

  return(
    <div className="screen">
      <div className="v-hero">
        <div className="v-hero-title">Public hash verification</div>
        <div className="v-hero-sub">Submit a SHA-256 hash to verify file authenticity and chain of custody. No login required.</div>
        <div className="v-row">
          <input className="v-inp" value={h} onChange={e=>setH(e.target.value.toLowerCase().replace(/[^a-f0-9]/g,''))} placeholder="3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b" maxLength={64} onKeyDown={e=>e.key==='Enter'&&check()}/>
          <button className="btn btn-primary" onClick={check} disabled={!validFmt||loading} style={{flexShrink:0}}>
            {loading?<span className="spin">◌</span>:<Ico n="verify" s={13}/>}
            {loading?'Checking…':'Verify'}
          </button>
        </div>
        <div className="v-char">
          {h.length===0&&'Enter a 64-character SHA-256 hex string'}
          {h.length>0&&h.length<64&&`${h.length} / 64 characters`}
          {h.length===64&&!validFmt&&'Invalid characters — only a-f and 0-9 allowed'}
          {validFmt&&'✓ Valid format'}
        </div>
      </div>

      {res&&(
        <div className={`rcard ${resClass}`}>
          <div className="rlbl">
            {res.status==='verified'&&'✓  File is authentic — integrity confirmed'}
            {res.status==='not_found'&&'—  Not found in this system'}
            {res.status==='tampered'&&'⚠  File has been modified since registration'}
          </div>
          {res.status!=='not_found'&&(
            <>
              <div className="divider" style={{borderColor:'rgba(0,0,0,.06)'}}/>
              <div className="g3" style={{gap:12,marginBottom:14}}>
                <div><div className="t4" style={{marginBottom:3}}>First registered</div><div style={{fontSize:13}}>{fmt(res.first_registered_at)}</div></div>
                <div><div className="t4" style={{marginBottom:3}}>Custody transfers</div><div style={{fontSize:13}}>{res.custody_transfer_count??0}</div></div>
                <div><div className="t4" style={{marginBottom:3}}>Report versions</div><div style={{fontSize:13}}>{res.report_versions_count??0}</div></div>
              </div>
              <div><div className="t4" style={{marginBottom:5}}>Verified hash</div>
                <div style={{display:'flex',alignItems:'flex-start',gap:8}}>
                  <div className="hash-full" style={{flex:1}}>{res.hash}</div>
                  <button className="btn-icon" onClick={()=>copy(res.hash)} title="Copy">{copied?<Ico n="check" s={12}/>:<Ico n="copy" s={12}/>}</button>
                </div>
              </div>
              <div className="t4" style={{marginTop:10}}>Checked at {fmt(res.verified_at)}</div>
            </>
          )}
        </div>
      )}

      <div className="card">
        <div className="card-hd"><span className="card-title">Try a known hash</span><span className="t3">Click any hash to prefill</span></div>
        <div style={{padding:'0 18px 8px'}}>
          {M.evidence.map(e=>(
            <div key={e.id} style={{display:'flex',alignItems:'center',gap:12,padding:'12px 0',borderBottom:'1px solid var(--border)'}}>
              <div style={{flex:1,minWidth:0}}>
                <div style={{fontSize:13,fontWeight:500,marginBottom:4}}>{e.filename}</div>
                <div className="hash-full" style={{cursor:'pointer',fontSize:11}} onClick={()=>setH(e.sha256_hash)}>{e.sha256_hash}</div>
              </div>
              <Bdg s={e.integrity_status}/>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ── Users ───────────────────────────────────────────────── */
function Users(){
  const [users,setUsers]=useState(M.users);
  const [showNew,setShowNew]=useState(false);
  const [form,setForm]=useState({full_name:'',email:'',role:'Examiner',password:''});
  const [editUser,setEditUser]=useState(null);

  const create=()=>{
    setUsers([...users,{id:`u${Date.now()}`,email:form.email,full_name:form.full_name,role:form.role,is_active:true,created_at:new Date().toISOString()}]);
    setForm({full_name:'',email:'',role:'Examiner',password:''});setShowNew(false);
  };

  const toggle=id=>setUsers(us=>us.map(u=>u.id===id?{...u,is_active:!u.is_active}:u));

  const roleColor={Admin:'b-archived',CaseManager:'b-active',LabTechnician:'b-open',Examiner:'b-in_progress',LegalReviewer:'b-court_ready'};

  return(
    <div className="screen">
      {showNew&&(
        <Modal title="Add user" onClose={()=>setShowNew(false)} footer={<><button className="btn btn-ghost" onClick={()=>setShowNew(false)}>Cancel</button><button className="btn btn-primary" onClick={create} disabled={!form.email||!form.full_name||!form.password}>Create user</button></>}>
          <div className="fgrp"><label className="flbl">Full name</label><input className="finp" value={form.full_name} onChange={e=>setForm({...form,full_name:e.target.value})} placeholder="Jane Smith"/></div>
          <div className="fgrp"><label className="flbl">Email</label><input className="finp" type="email" value={form.email} onChange={e=>setForm({...form,email:e.target.value})} placeholder="jane.smith@forensics.local"/></div>
          <div className="fgrp">
            <label className="flbl">Role</label>
            <select className="finp fsel" value={form.role} onChange={e=>setForm({...form,role:e.target.value})}>
              {['CaseManager','LabTechnician','Examiner','LegalReviewer','Admin'].map(r=><option key={r}>{r}</option>)}
            </select>
          </div>
          <div className="fgrp"><label className="flbl">Temporary password</label><input className="finp" type="password" value={form.password} onChange={e=>setForm({...form,password:e.target.value})} placeholder="Minimum 12 characters"/></div>
          <div className="alert a-info" style={{marginTop:4}}><Ico n="shield" s={13}/>Role changes are logged in the audit log with before/after values.</div>
        </Modal>
      )}
      {editUser&&(
        <Modal title={`Edit — ${editUser.full_name}`} onClose={()=>setEditUser(null)} footer={<><button className="btn btn-ghost" onClick={()=>setEditUser(null)}>Cancel</button><button className="btn btn-primary" onClick={()=>{setUsers(us=>us.map(u=>u.id===editUser.id?editUser:u));setEditUser(null);}}>Save changes</button></>}>
          <div className="fgrp"><label className="flbl">Full name</label><input className="finp" value={editUser.full_name} onChange={e=>setEditUser({...editUser,full_name:e.target.value})}/></div>
          <div className="fgrp"><label className="flbl">Role</label>
            <select className="finp fsel" value={editUser.role} onChange={e=>setEditUser({...editUser,role:e.target.value})}>
              {['CaseManager','LabTechnician','Examiner','LegalReviewer','Admin'].map(r=><option key={r}>{r}</option>)}
            </select>
          </div>
          <div className="alert a-warn"><Ico n="alert" s={13}/>A user cannot hold both Examiner and Legal Reviewer roles on the same case.</div>
        </Modal>
      )}

      <div className="rb" style={{marginBottom:18}}>
        <span className="t3">{users.length} users · {users.filter(u=>u.is_active).length} active</span>
        <button className="btn btn-primary" onClick={()=>setShowNew(true)}><Ico n="plus" s={13}/>Add user</button>
      </div>
      <div className="card">
        <table className="tbl">
          <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Created</th><th/></tr></thead>
          <tbody>
            {users.map(u=>(
              <tr key={u.id}>
                <td><div style={{display:'flex',alignItems:'center',gap:8}}><div className="avatar" style={{width:26,height:26,fontSize:10,flexShrink:0}}>{u.full_name.split(' ').map(n=>n[0]).join('')}</div><span style={{fontWeight:500}}>{u.full_name}</span></div></td>
                <td className="t3 mono" style={{fontSize:12}}>{u.email}</td>
                <td><span className={`badge ${roleColor[u.role]||'b-draft'}`}>{u.role}</span></td>
                <td>
                  <div style={{display:'flex',alignItems:'center',gap:6}}>
                    <div style={{width:7,height:7,borderRadius:'50%',background:u.is_active?'var(--green)':'var(--text-4)'}}/>
                    <span style={{fontSize:12,color:u.is_active?'var(--green)':'var(--text-3)'}}>{u.is_active?'Active':'Inactive'}</span>
                  </div>
                </td>
                <td className="t3" style={{fontSize:11}}>{fmtDate(u.created_at)}</td>
                <td>
                  <div className="row" style={{gap:4}}>
                    <button className="btn btn-ghost btn-sm" onClick={()=>setEditUser({...u})}>Edit</button>
                    <button className="btn btn-ghost btn-sm" style={{color:u.is_active?'var(--red)':'var(--green)'}} onClick={()=>toggle(u.id)}>{u.is_active?'Deactivate':'Reactivate'}</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ── Audit ───────────────────────────────────────────────── */
function Audit(){
  const [filter,setFilter]=useState('');
  const [roleF,setRoleF]=useState('');

  const actionStyle={
    'evidence.tamper_detected':{color:'var(--red)',fontWeight:600},
    'report.locked':{color:'var(--purple)',fontWeight:500},
    'evidence.uploaded':{color:'var(--green)'},
    'custody.transfer_accepted':{color:'var(--blue)'},
    'custody.transfer_initiated':{color:'#0284C7'},
    'verify.hash_queried':{color:'var(--text-3)'},
  };

  const filtered=M.audit.filter(a=>{
    if(filter&&!a.action_type.includes(filter))return false;
    if(roleF&&a.actor_role!==roleF)return false;
    return true;
  });

  return(
    <div className="screen">
      <div className="alert a-info" style={{marginBottom:18}}><Ico n="shield" s={13}/>Audit log is append-only and stored in a separate schema. No UPDATE or DELETE is permitted — even for administrators.</div>

      <div className="card" style={{marginBottom:18}}>
        <div className="card-hd">
          <span className="card-title">Filters</span>
          <button className="btn btn-ghost btn-sm" onClick={()=>{setFilter('');setRoleF('')}}><Ico n="x" s={12}/>Clear</button>
        </div>
        <div className="card-bd" style={{paddingTop:14}}>
          <div className="g2" style={{gap:14}}>
            <div className="fgrp" style={{margin:0}}>
              <label className="flbl">Action type</label>
              <select className="finp fsel" value={filter} onChange={e=>setFilter(e.target.value)}>
                <option value="">All actions</option>
                {[...new Set(M.audit.map(a=>a.action_type))].map(t=><option key={t}>{t}</option>)}
              </select>
            </div>
            <div className="fgrp" style={{margin:0}}>
              <label className="flbl">Role</label>
              <select className="finp fsel" value={roleF} onChange={e=>setRoleF(e.target.value)}>
                <option value="">All roles</option>
                {[...new Set(M.audit.map(a=>a.actor_role).filter(Boolean))].map(r=><option key={r}>{r}</option>)}
              </select>
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-hd">
          <span className="card-title">Audit log</span>
          <div className="row" style={{gap:8}}>
            <span className="t3">{filtered.length} entries</span>
            <button className="btn btn-ghost btn-sm"><Ico n="download" s={12}/>Export CSV</button>
          </div>
        </div>
        <table className="tbl">
          <thead><tr><th>Timestamp</th><th>Action</th><th>Actor</th><th>Resource</th><th>IP address</th><th>Result</th><th>Detail</th></tr></thead>
          <tbody>
            {filtered.map(a=>(
              <tr key={a.id}>
                <td className="t3 mono" style={{fontSize:11,whiteSpace:'nowrap'}}>{fmt(a.timestamp)}</td>
                <td>
                  <span className="mono" style={{fontSize:11,...(actionStyle[a.action_type]||{color:'var(--text-2)'})}}>{a.action_type}</span>
                </td>
                <td>
                  <div style={{fontSize:12}}>{a.actor_role||<span className="t4">Public</span>}</div>
                  <div className="t4">{a.actor_id?M.users.find(u=>u.id===a.actor_id)?.full_name||a.actor_id:'unauthenticated'}</div>
                </td>
                <td className="t3">{a.resource_type}<div className="mono t4">{String(a.resource_id).slice(0,10)}</div></td>
                <td><span className="mono" style={{fontSize:11}}>{a.ip_address}</span></td>
                <td>
                  <span style={{fontSize:11,fontWeight:600,color:a.result==='success'?'var(--green)':a.result==='failure'?'var(--red)':'var(--amber)'}}>{a.result}</span>
                </td>
                <td>
                  <div style={{fontSize:11,color:'var(--text-3)',maxWidth:180,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>
                    {Object.entries(a.detail).map(([k,v])=>`${k}: ${String(v).slice(0,20)}`).join(' · ')}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length===0&&<div className="empty"><div className="empty-icon">🔍</div>No entries match the current filters</div>}
      </div>
    </div>
  );
}

/* ════════════ ROOT ════════════════════════════════════════ */
const NAV=[
  {id:'dashboard',label:'Dashboard',icon:'home',roles:['all']},
  {id:'cases',label:'Cases',icon:'cases',roles:['all']},
  {id:'evidence',label:'Evidence',icon:'evidence',roles:['CaseManager','LabTechnician','Examiner','Admin']},
  {id:'custody',label:'Chain of custody',icon:'custody',roles:['all']},
  {id:'tasks',label:'Tasks',icon:'tasks',roles:['CaseManager','Examiner']},
  {id:'reports',label:'Reports',icon:'reports',roles:['Examiner','LegalReviewer','CaseManager']},
  {id:'verify',label:'Verify hash',icon:'verify',roles:['all']},
  {id:'users',label:'Users',icon:'users',roles:['Admin']},
  {id:'audit',label:'Audit log',icon:'audit',roles:['Admin']},
];

const TITLES={dashboard:'Dashboard',cases:'Cases',evidence:'Evidence registry',custody:'Chain of custody',tasks:'Tasks',reports:'Reports',verify:'Verify hash',users:'Users',audit:'Audit log'};

function App(){
  const [session,setSession]=useState(null);
  const [screen,setScreen]=useState('dashboard');

  if(!session)return <Login onLogin={s=>{setSession(s);setScreen('dashboard');}}/>;

  const visible=NAV.filter(n=>n.roles.includes('all')||n.roles.includes(session.role));
  const screens={dashboard:<Dashboard session={session} nav={setScreen}/>,cases:<Cases session={session}/>,evidence:<Evidence session={session}/>,custody:<Custody session={session}/>,tasks:<Tasks session={session}/>,reports:<Reports session={session}/>,verify:<Verify/>,users:<Users/>,audit:<Audit/>};

  return(
    <div className="shell">
      <aside className="sidebar">
        <div className="sb-logo">
          <div className="logo-row">
            <div className="logo-icon"><Ico n="shield" s={16}/></div>
            <div><div className="logo-text">ForensicChain</div><div className="logo-sub">Case management</div></div>
          </div>
        </div>
        <div className="sb-section">
          {visible.map(n=>(
            <button key={n.id} className={`nav-btn ${screen===n.id?'on':''}`} onClick={()=>setScreen(n.id)}>
              <Ico n={n.icon} s={15}/>{n.label}
            </button>
          ))}
        </div>
        <div className="sb-footer">
          <div className="user-row">
            <div className="avatar">{session.name?.[0]?.toUpperCase()||'U'}</div>
            <div><div className="u-name">{session.name}</div><div className="u-role">{session.role}</div></div>
          </div>
        </div>
      </aside>
      <main className="main">
        <div className="topbar">
          <div><div className="tb-title">{TITLES[screen]}</div><div className="tb-sub">CASE-2024-00142 — Insider Trading Investigation</div></div>
          <div className="tb-right">
            <div className="ibar ok" style={{padding:'5px 10px',fontSize:11,marginBottom:0}}><Ico n="shield" s={12}/>Chain intact</div>
          </div>
        </div>
        <div className="content">
          {screens[screen]||<div className="empty"><div className="empty-icon">🔒</div>Access restricted for {session.role}</div>}
        </div>
      </main>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App/>);
