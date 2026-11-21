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
  name: 'SatHack Sensor (Mumbai, IN)',
  lat: 19.076,
  lon: 72.8777,
};

// ============================================================================
// MOCK HONEY-TOKENS DATA (used when VITE_USE_MOCK=true)
// ============================================================================

const MOCK_NOW = Date.now();
const MOCK_HONEY_TOKENS = [
  {
    id: 103,
    created_at: new Date(MOCK_NOW - 4 * 60 * 1000).toISOString(),
    token_masked: 'bt_live_98a7••••',
    kind: 'api_key',
    issued_to_ip: '203.0.113.7',
    issued_on_path: '/.env',
    status: 'used',
    used_count: 1,
    first_used_at: new Date(MOCK_NOW - 2 * 60 * 1000).toISOString(),
    last_used_at: new Date(MOCK_NOW - 2 * 60 * 1000).toISOString(),
    used_by_ip: '203.0.113.7',
    used_on_path: '/admin/login',
    seconds_to_use: 87,
  },
  {
    id: 102,
    created_at: new Date(MOCK_NOW - 4 * 60 * 1000).toISOString(),
    token_masked: 'x9K2mP7qL4vR••••',
    kind: 'password',
    issued_to_ip: '203.0.113.7',
    issued_on_path: '/.env',
    status: 'issued',
    used_count: 0,
    first_used_at: null,
    last_used_at: null,
    used_by_ip: null,
    used_on_path: null,
    seconds_to_use: null,
  },
  {
    id: 101,
    created_at: new Date(MOCK_NOW - 11 * 60 * 1000).toISOString(),
    token_masked: 'bt_live_4c1e••••',
    kind: 'api_key',
    issued_to_ip: '198.51.100.24',
    issued_on_path: '/api/v1/config',
    status: 'issued',
    used_count: 0,
    first_used_at: null,
    last_used_at: null,
    used_by_ip: null,
    used_on_path: null,
    seconds_to_use: null,
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

function usePolling(endpoint, { mockData, intervalMs = 3500, enabled = true }) {
  const [data, setData] = useState(() => (USE_MOCK ? mockData : null));
  const [loading, setLoading] = useState(!USE_MOCK);
  const [error, setError] = useState
