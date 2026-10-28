"""
DFEMS - Database Adapter with Transparent SQLite Fallback
Provides a MongoDB-compatible interface using PyMongo when available/connected,
or an automatic embedded SQLite document store when MongoDB is not running (e.g. Render free tier).
"""

import os
import json
import re
import sqlite3
import time
from werkzeug.security import generate_password_hash
from bson.objectid import ObjectId
from pymongo import MongoClient
from pymongo.errors import PyMongoError


class SQLiteCursor:
    def __init__(self, docs):
        self._docs = list(docs)
        self._sort_key = None
        self._sort_dir = 1
        self._limit = None

    def sort(self, key, direction=1):
        self._sort_key = key
        self._sort_dir = direction
        return self

    def limit(self, count):
        self._limit = count
        return self

    def _get_results(self):
        res = list(self._docs)
        if self._sort_key:
            res = sorted(
                res,
                key=lambda d: str(d.get(self._sort_key, "")),
                reverse=(self._sort_dir == -1 or str(self._sort_dir).lower() == "desc")
            )
        if self._limit is not None:
            res = res[:self._limit]
        return res

    def __iter__(self):
        return iter(self._get_results())

    def __len__(self):
        return len(self._get_results())

    def __getitem__(self, index):
        return self._get_results()[index]


class InsertResult:
    def __init__(self, inserted_id):
        self.inserted_id = inserted_id


class DeleteResult:
    def __init__(self, deleted_count):
        self.deleted_count = deleted_count


class UpdateResult:
    def __init__(self, matched_count, modified_count, upserted_id=None):
        self.matched_count = matched_count
        self.modified_count = modified_count
        self.upserted_id = upserted_id


def doc_matches(doc, filter_dict):
    if not filter_dict:
        return True
    for key, val in filter_dict.items():
        if key == "$or":
            if not any(doc_matches(doc, sub) for sub in val):
                return False
            continue
        if key == "$and":
            if not all(doc_matches(doc, sub) for sub in val):
                return False
            continue

        doc_val = doc.get(key)
        if isinstance(val, dict):
            if "$regex" in val:
                pattern = val["$regex"]
                flags = re.IGNORECASE if "i" in val.get("$options", "") else 0
                if doc_val is None or not re.search(pattern, str(doc_val), flags):
                    return False
            if "$in" in val:
                allowed = [str(x) for x in val["$in"]]
                if str(doc_val) not in allowed:
                    return False
        else:
            if str(doc_val) != str(val):
                return False
    return True


class SQLiteCollection:
    def __init__(self, db_path, name):
        self.db_path = db_path
        self.name = name
        self._init_table()

    def _execute(self, query, params=(), fetchone=False, fetchall=False, commit=False):
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=15.0)
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA busy_timeout=5000;")
            cur = conn.cursor()
            cur.execute(query, params)
            if commit:
                conn.commit()
            if fetchone:
                return cur.fetchone()
            if fetchall:
                return cur.fetchall()
            return cur
        finally:
            conn.close()

    def _init_table(self):
        self._execute(f"""
            CREATE TABLE IF NOT EXISTS col_{self.name} (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """, commit=True)

    def create_index(self, key, unique=False):
        pass

    def _deserialize(self, doc_json):
        doc = json.loads(doc_json)
        if "_id" in doc:
            try:
                doc["_id"] = ObjectId(doc["_id"])
            except Exception:
                pass
        for field in ("case_id", "evidence_id"):
            if field in doc and doc[field]:
                try:
                    doc[field] = ObjectId(doc[field])
                except Exception:
                    pass
        return doc

    def _serialize(self, doc):
        d = dict(doc)
        for k, v in d.items():
            if isinstance(v, ObjectId):
                d[k] = str(v)
        return json.dumps(d)

    def _fetch_all(self):
        rows = self._execute(
            f"SELECT data FROM col_{self.name} ORDER BY created_at ASC",
            fetchall=True
        )
        return [self._deserialize(r[0]) for r in rows]

    def insert_one(self, doc):
        doc = dict(doc)
        if "_id" not in doc:
            doc["_id"] = ObjectId()
        elif not isinstance(doc["_id"], ObjectId):
            try:
                doc["_id"] = ObjectId(str(doc["_id"]))
            except Exception:
                pass

        doc_id = str(doc["_id"])
        data_str = self._serialize(doc)
        now_ts = time.time()

        self._execute(
            f"INSERT OR REPLACE INTO col_{self.name} (id, data, created_at) VALUES (?, ?, ?)",
            (doc_id, data_str, now_ts),
            commit=True
        )
        return InsertResult(doc["_id"])

    def find_one(self, filter_dict=None):
        if filter_dict and "_id" in filter_dict and len(filter_dict) == 1:
            id_str = str(filter_dict["_id"])
            row = self._execute(
                f"SELECT data FROM col_{self.name} WHERE id = ?",
                (id_str,),
                fetchone=True
            )
            if row:
                return self._deserialize(row[0])
            return None

        all_docs = self._fetch_all()
        for d in all_docs:
            if doc_matches(d, filter_dict):
                return d
        return None

    def find(self, filter_dict=None):
        all_docs = self._fetch_all()
        matching = [d for d in all_docs if doc_matches(d, filter_dict)]
        return SQLiteCursor(matching)

    def count_documents(self, filter_dict=None):
        if not filter_dict:
            row = self._execute(f"SELECT COUNT(*) FROM col_{self.name}", fetchone=True)
            return row[0] if row else 0
        return len(self.find(filter_dict))

    def update_one(self, filter_dict, update_dict, upsert=False):
        all_docs = self._fetch_all()
        for d in all_docs:
            if doc_matches(d, filter_dict):
                if "$set" in update_dict:
                    d.update(update_dict["$set"])
                doc_id = str(d["_id"])
                data_str = self._serialize(d)
                self._execute(
                    f"UPDATE col_{self.name} SET data = ? WHERE id = ?",
                    (data_str, doc_id),
                    commit=True
                )
                return UpdateResult(1, 1)

        if upsert:
            new_doc = dict(filter_dict)
            if "$set" in update_dict:
                new_doc.update(update_dict["$set"])
            res = self.insert_one(new_doc)
            return UpdateResult(0, 0, upserted_id=res.inserted_id)

        return UpdateResult(0, 0)

    def delete_one(self, filter_dict):
        all_docs = self._fetch_all()
        for d in all_docs:
            if doc_matches(d, filter_dict):
                doc_id = str(d["_id"])
                self._execute(
                    f"DELETE FROM col_{self.name} WHERE id = ?",
                    (doc_id,),
                    commit=True
                )
                return DeleteResult(1)
        return DeleteResult(0)

    def delete_many(self, filter_dict):
        all_docs = self._fetch_all()
        to_delete = [str(d["_id"]) for d in all_docs if doc_matches(d, filter_dict)]
        if to_delete:
            conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=15.0)
            try:
                for doc_id in to_delete:
                    conn.execute(f"DELETE FROM col_{self.name} WHERE id = ?", (doc_id,))
                conn.commit()
            finally:
                conn.close()
        return DeleteResult(len(to_delete))


class SQLiteDatabase:
    def __init__(self, db_path):
        self.db_path = db_path
        self._collections = {}

    def __getitem__(self, name):
        if name not in self._collections:
            self._collections[name] = SQLiteCollection(self.db_path, name)
        return self._collections[name]

    def __getattr__(self, name):
        return self[name]


def get_database(base_dir, mongo_uri, mongo_db_name):
    """
    Attempts to connect to MongoDB. If MongoDB is unavailable, transparently
    falls back to an embedded SQLite document store with default demo accounts.
    """
    use_sqlite = False
    client = None
    db = None

    try:
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=2000)
        client.admin.command("ping")
        db = client[mongo_db_name]
        print(f"[DFEMS] Successfully connected to live MongoDB: {mongo_uri}")
    except Exception as e:
        print(f"[DFEMS] MongoDB unreachable ({e}). Activating persistent SQLite document fallback.")
        use_sqlite = True

    if use_sqlite:
        sqlite_file = os.path.join(base_dir, "dfems_storage.db")
        db = SQLiteDatabase(sqlite_file)

        # Seed initial demo credentials if users table is empty
        users_col = db["users"]
        if users_col.count_documents({}) == 0:
            users_col.insert_one({
                "username": "ishan1",
                "password_hash": generate_password_hash("123"),
                "role": "admin"
            })
            users_col.insert_one({
                "username": "ishan",
                "password_hash": generate_password_hash("123"),
                "role": "investigator"
            })
            print("[DFEMS] Seeded default demo credentials: 'ishan1' (admin) and 'ishan' (investigator).")

    return db, use_sqlite
