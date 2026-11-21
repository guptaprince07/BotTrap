// frontend/src/mockData.js
// Fake data matching the API contract (Section 5.7). Used when VITE_USE_MOCK=true.
export const USE_MOCK = import.meta.env.VITE_USE_MOCK === 'true';

const ago = (min) => new Date(Date.now() - min * 60000).toISOString();

const EVENTS = [
  { id: 6, created_at: ago(1), ip: '203.0.113.7', country: 'Russia', city: 'Moscow', lat: 55.75, lon: 37.61,
    method: 'POST', path: '/admin/login', query: '', body: "username=admin&password=' OR 1=1 --",
    user_agent: 'sqlmap/1.7', status: 'classified', attack_type: 'SQL Injection', severity: 'High',
    mitre_id: 'T1190', mitre_name: 'Exploit Public-Facing Application', likely_tool: 'sqlmap',
    explanation: 'Tautology payload tries to bypass the login query.',
    recommended_rule: 'if ($request_body ~* "(\'|%27)\\s*(or|and)\\s+\\d+=\\d+") { return 403; }', source: 'rule' },
  { id: 5, created_at: ago(3), ip: '198.51.100.23', country: 'China', city: 'Beijing', lat: 39.9, lon: 116.4,
    method: 'GET', path: '/.env', query: '', body: '', user_agent: 'curl/8.0',
    status: 'classified', attack_type: 'Sensitive File Probe', severity: 'High',
    mitre_id: 'T1552.001', mitre_name: 'Credentials In Files', likely_tool: 'curl',
    explanation: 'Attacker is looking for leaked environment secrets.',
    recommended_rule: 'location ~ /\\.env { return 403; }', source: 'rule' },
  { id: 4, created_at: ago(6), ip: '192.0.2.44', country: 'Brazil', city: 'Sao Paulo', lat: -23.55, lon: -46.63,
    method: 'GET', path: '/search', query: 'q=<script>alert(1)</script>', body: '', user_agent: 'Mozilla/5.0',
    status: 'classified', attack_type: 'XSS', severity: 'Medium',
    mitre_id: 'T1190', mitre_name: 'Exploit Public-Facing Application', likely_tool: 'unknown',
    explanation: 'Script tag injected in a query parameter.',
    recommended_rule: 'if ($args ~* "<script") { return 403; }', source: 'llm' },
  { id: 3, created_at: ago(9), ip: '203.0.113.99', country: 'United States', city: 'Ashburn', lat: 39.04, lon: -77.49,
    method: 'GET', path: '/wp-login.php', query: '', body: '', user_agent: 'Nikto/2.5',
    status: 'classified', attack_type: 'Vulnerability Scan', severity: 'Medium',
    mitre_id: 'T1595.002', mitre_name: 'Vulnerability Scanning', likely_tool: 'nikto',
    explanation: 'Automated scanner fingerprint in the User-Agent.',
    recommended_rule: 'if ($http_user_agent ~* "nikto") { return 403; }', source: 'rule' },
  { id: 2, created_at: ago(12), ip: '198.51.100.8', country: 'India', city: 'Mumbai', lat: 19.07, lon: 72.87,
    method: 'GET', path: '/download', query: 'file=../../etc/passwd', body: '', user_agent: 'python-requests/2.31',
    status: 'classified', attack_type: 'Path Traversal', severity: 'High',
    mitre_id: 'T1083', mitre_name: 'File and Directory Discovery', likely_tool: 'python-requests',
    explanation: 'Tries to read system files using ../ sequences.',
    recommended_rule: 'if ($args ~* "\\.\\./") { return 403; }', source: 'rule' },
  { id: 1, created_at: ago(15), ip: '192.0.2.200', country: 'Germany', city: 'Berlin', lat: 52.52, lon: 13.4,
    method: 'POST', path: '/api/v1/login', query: '', body: 'username=root&password=123456',
    user_agent: 'Hydra', status: 'classified', attack_type: 'Brute Force', severity: 'Medium',
    mitre_id: 'T1110', mitre_name: 'Brute Force', likely_tool: 'hydra',
    explanation: 'Repeated password guesses against the login API.',
    recommended_rule: 'limit_req zone=login burst=5 nodelay;', source: 'rule' },
];

export const mockStats = () => ({
  total: 123, last_hour: 40, unique_ips: 17, pending: 2,
  by_type: { 'SQL Injection': 40, XSS: 18, 'Brute Force': 25, 'Path Traversal': 12, 'Vulnerability Scan': 20, 'Sensitive File Probe': 8 },
  by_severity: { Low: 10, Medium: 50, High: 50, Critical: 13 },
  threat_level: 'High',
});

export const mockEvents = (filters = {}) => ({
  events: EVENTS.filter(
    (e) =>
      (!filters.severity || e.severity === filters.severity) &&
      (!filters.attack_type || e.attack_type === filters.attack_type)
  ),
});

export const mockTimeline = () => ({
  points: [5, 8, 12, 9, 20, 15, 22, 18, 30, 25].map((count, i) => ({ t: ago((9 - i) * 6), count })),
});

export const mockMitre = () => ({
  items: [
    { mitre_id: 'T1190', name: 'Exploit Public-Facing Application', count: 58 },
    { mitre_id: 'T1110', name: 'Brute Force', count: 25 },
    { mitre_id: 'T1595.002', name: 'Vulnerability Scanning', count: 20 },
    { mitre_id: 'T1083', name: 'File and Directory Discovery', count: 12 },
    { mitre_id: 'T1552.001', name: 'Credentials In Files', count: 8 },
  ],
});

export const mockGeo = () => ({
  points: EVENTS.map((e) => ({ ip: e.ip, lat: e.lat, lon: e.lon, country: e.country, count: 10 + e.id * 3 })),
});

export const mockAttackers = () => ({
  attackers: [
    { ip: '203.0.113.7', country: 'Russia', count: 40, top_type: 'SQL Injection' },
    { ip: '192.0.2.200', country: 'Germany', count: 25, top_type: 'Brute Force' },
    { ip: '198.51.100.23', country: 'China', count: 18, top_type: 'Sensitive File Probe' },
    { ip: '203.0.113.99', country: 'United States', count: 12, top_type: 'Vulnerability Scan' },
  ],
});
