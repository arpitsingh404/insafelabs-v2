import os
from motor.motor_asyncio import AsyncIOMotorClient

mongo_url = os.environ.get("MONGO_URL")
db_name = os.environ.get("DB_NAME")

if not mongo_url or not db_name:
    raise RuntimeError(
        "MONGO_URL and DB_NAME must be set — copy backend/.env.example to backend/.env and fill it in"
    )

client = AsyncIOMotorClient(mongo_url)
db = client[db_name]
