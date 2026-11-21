HoneyLens: Pitch

Theme: AI & Cybersecurity (threat detection, fraud prevention, secure systems)
Team: Prince, Sejal, Neha, Vidanshi, Miljot

One-line pitch

HoneyLens is an AI-powered honeypot that attracts attackers, explains every attack in plain English, and hands you the firewall rule to block it, all on a free, live dashboard.

1. Problem
Servers are scanned and attacked within minutes of going online.
Small organisations (colleges, clinics, small businesses) have no security team and no budget.
Security logs are raw and unreadable for non-experts, so attacks go unnoticed.
2. Solution
A fake admin portal and fake API attract bots and attackers. They never execute anything and hold no real data.
Every request is captured and classified: regex rules first (instant, free), then an LLM only when rules are unsure.
Each attack is mapped to MITRE ATT&CK, given a severity, a plain-English explanation and a ready-to-use Nginx/firewall rule.
A live dashboard shows the feed, timeline, attack types, MITRE chart, world map and top attackers. One click generates an incident report.
3. Architecture
 Attackers --> HONEYPOT (Flask) --> DB (events, status=pending)
                                      |
                  PIPELINE WORKER <---+   geo -> rules -> (LLM if unsure)
                                      |
 React Dashboard <-- polls every 3s -- DASHBOARD API (Flask) <-- DB
The database acts as the queue, so services stay independent.
Stack: React (Vite) + Flask + PostgreSQL + free LLM API (Groq or Gemini).
Hosting: Vercel + Render + Neon, all free tier. Total cost: Rs 0.
4. What makes it different
Hybrid classification: rules for speed and cost, LLM for the unknown.
Actionable output: not just "attack detected" but "here is the rule to block it".
Safe by design: no input is ever executed or reflected. The LLM has no tools and only returns validated JSON.
Demo-proof: an attack simulator with global IPs guarantees live traffic.
5. Impact
Gives small organisations an early-warning system at zero cost.
Turns unreadable logs into plain-English insight anyone can act on.
Builds a dataset of real attack patterns for learning and research.
6. Limitations (we are honest about these)
Free-tier hosting can sleep and is rate-limited.
The LLM can be wrong, so its output is validated and falls back safely.
A honeypot is an early-warning and research tool, not a replacement for a firewall.
7. Future scope
Automatically sync blocking rules to a firewall or reverse proxy.
Telegram / email alerts for Critical events.
A network of honeypots sharing threat intelligence.
Attacker behaviour profiling across sessions.
Closing line

"Attackers are already probing every server. HoneyLens lets small teams watch them, understand them, and block them, for free."