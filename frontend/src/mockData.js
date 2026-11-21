const twoMinutesAgo = new Date(Date.now() - 2 * 60 * 1000).toISOString();
const fourMinutesAgo = new Date(Date.now() - 4 * 60 * 1000).toISOString();
const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000).toISOString();

export const MOCK_HONEY_TOKENS = [
  {
    id: 103,
    created_at: fourMinutesAgo,
    token_masked: "bt_live_98a7••••",
    kind: "api_key",
    issued_to_ip: "203.0.113.7",
    issued_on_path: "/.env",
    status: "used",
    used_count: 1,
    first_used_at: twoMinutesAgo,
    last_used_at: twoMinutesAgo,
    used_by_ip: "203.0.113.7",
    used_on_path: "/admin/login",
    seconds_to_use: 87,
  },
  {
    id: 102,
    created_at: fourMinutesAgo,
    token_masked: "x9K2mP7qL4vR••••",
    kind: "password",
    issued_to_ip: "203.0.113.7",
    issued_on_path: "/.env",
    status: "issued",
    used_count: 0,
    first_used_at: null,
    last_used_at: null,
    used_by_ip: null,
    used_on_path: null,
    seconds_to_use: null,
  },
  {
    id: 101,
    created_at: tenMinutesAgo,
    token_masked: "bt_live_4c1e••••",
    kind: "api_key",
    issued_to_ip: "198.51.100.24",
    issued_on_path: "/api/v1/config",
    status: "issued",
    used_count: 0,
    first_used_at: null,
    last_used_at: null,
    used_by_ip: null,
    used_on_path: null,
    seconds_to_use: null,
  },
];

export const MOCK_TOKEN_STATS = {
  issued: 12,
  used: 2,
  readers: 9,
  avg_seconds_to_use: 87,
  last_used_at: twoMinutesAgo,
};
