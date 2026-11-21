import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///honeylens.db")

API_PORT = int(os.getenv("API_PORT", 5001))

ALLOWED_ORIGIN = os.getenv("ALLOWED_ORIGIN", "http://localhost:5173")

RUN_WORKER = os.getenv("RUN_WORKER", "true").lower() == "true"
