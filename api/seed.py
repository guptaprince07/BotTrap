from datetime import datetime, timedelta
from shared.db import SessionLocal, make_token
from shared.models import Event, HoneyToken


def seed_honey_tokens():
    now = datetime.utcnow()
    with SessionLocal() as db:
        if db.query(HoneyToken).count() > 0:
            return

        # 1. Issued (unused) honey-token
        issued = HoneyToken(
            created_at=now - timedelta(minutes=14),
            token=make_token("password"),
            kind="password",
            issued_to_ip="198.51.100.24",
            issued_on_path="/.git/config",
            issued_user_agent="git/2.43.0",
            status="issued",
            used_count=0,
        )

        # 2. Used honey-token (leaked at /.env, used 87s later on /admin/login)
        used_created = now - timedelta(minutes=3, seconds=27)
        used_at = used_created + timedelta(seconds=87)
        used = HoneyToken(
            created_at=used_created,
            token=make_token("api_key"),
            kind="api_key",
            issued_to_ip="203.0.113.7",
            issued_on_path="/.env",
            issued_user_agent="curl/8.5.0",
            status="used",
            used_count=1,
            first_used_at=used_at,
            last_used_at=used_at,
            used_by_ip="203.0.113.7",
            used_on_path="/admin/login",
            seconds_to_use=87,
        )
        db.add_all([issued, used])

        # Matching Critical feed event (adjust column names if your Event model differs)
        event = Event(
            created_at=used_at,
            ip="203.0.113.7",
            method="POST",
            path="/admin/login",
            user_agent="curl/8.5.0",
            status="classified",
            attack_type="Honey-Token Used",
            severity="Critical",
            mitre_id="T1078",
            mitre_name="Valid Accounts",
            likely_tool="unknown",
            explanation=(
                "Used the fake api_key leaked at /.env 87s earlier. "
                "The attacker read the leak and tried it."
            ),
            recommended_rule="deny 203.0.113.7;   # Nginx: block this IP",
            source="honey_token",
        )
        db.add(event)
        db.commit()
