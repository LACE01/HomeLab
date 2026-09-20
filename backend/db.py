"""MongoDB connection singleton.

Driver is selectable via USE_PYMONGO_ASYNC:
  * unset / false (DEFAULT): motor (AsyncIOMotorClient) -- the proven driver.
  * true: PyMongo's native async client (AsyncMongoClient), the long-term
    replacement now that motor is in maintenance-only mode.

The collection API used across this app (find/find_one/insert_*/update_*/aggregate/
count_documents/create_index + cursor.to_list) is the same shape on both, so most
code is driver-agnostic. This is DEFAULT-SAFE: nothing changes unless you opt in,
and you can flip back by unsetting the env var. Validate thoroughly before trusting
the pymongo path in production -- it is not yet exercised by CI.
"""
import os

_use_pymongo = (os.environ.get("USE_PYMONGO_ASYNC", "").lower() in ("1", "true", "yes"))

if _use_pymongo:
    from pymongo import AsyncMongoClient  # pymongo >= 4.13
    _client = AsyncMongoClient(os.environ["MONGO_URL"])
    DRIVER = "pymongo-async"
else:
    from motor.motor_asyncio import AsyncIOMotorClient
    _client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    DRIVER = "motor"

db = _client[os.environ["DB_NAME"]]
