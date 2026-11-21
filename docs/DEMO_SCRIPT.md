HoneyLens: 5-Minute Demo Script

Presenters: split the script across the team (suggested: Miljot opens/closes, Prince runs the attack, Neha explains the AI part).

Before you go on stage (T-10 min)
[ ] Open the live dashboard URL and the live honeypot URL. Free hosts sleep, so load both now.
[ ] Check UptimeRobot is green.
[ ] Terminal ready with: python attack_sim/simulate.py --target <honeypot_url>
[ ] Backup ready: docker-compose up + python api/seed.py, and a 1-minute screen recording.
[ ] Browser zoom so the world map and the feed are both visible.
1. Problem (0:00 to 0:30)

"Every server on the internet is attacked within minutes. Small colleges, clinics and shops have no security team, and raw logs are unreadable. We built HoneyLens: a trap that catches attackers and explains every attack in plain English."

2. Show the bait (0:30 to 1:00)

Open the fake admin page (/admin). "This looks real, but it connects to nothing. It never runs anything the attacker sends. It only records."

3. Attack live (1:00 to 2:00)

Run python attack_sim/simulate.py --target <honeypot_url>. Switch to the dashboard and point out, in order:

Stat cards counting up.
Live feed filling with new events.
Timeline chart rising.
Pins appearing on the world map.
4. AI explanation (2:00 to 3:00)

Click one event in the live feed. Show: payload, attack type, severity, MITRE ATT&CK ID, plain-English explanation, and the ready-to-use Nginx/firewall rule. Say: "Rules classify the obvious attacks instantly and for free. The LLM is called only when the rules are unsure. That keeps it fast and cheap."

5. Attacker profile (3:00 to 3:45)

Show Top Attackers and the map. Click "Generate incident report" and read one sentence of it. Use the filter bar to show only Critical or only SQL Injection.

6. Impact, limits, future (3:45 to 4:30)
Impact: a cheap early-warning system for colleges, clinics and small businesses.
Limits: free-tier hosting, the LLM can be wrong, and this is not a replacement for a firewall.
Future: push blocking rules to the firewall automatically, Telegram alerts, a network of honeypots.
Q&A buffer (4:30 to 5:00)
If something breaks
Problem	Do this
Live site is asleep	Wait 30 seconds, refresh. Else switch to local docker-compose up
Network is down	Play the 1-minute screen recording
LLM is rate-limited	Say: "Rules still classify everything; the AI is a second opinion"
Dashboard empty	Run simulate.py again, or python api/seed.py
Likely questions
Is it safe? The honeypot never executes or reflects input and holds no real data. Payloads are shown as plain text.
Why rules first, then LLM? Speed, cost, and the free API limit.
What if the LLM lies? Output is validated: the MITRE ID must exist in our list, otherwise we fall back to "Other".
Real attackers or simulated? Both. The simulator guarantees traffic for the demo.