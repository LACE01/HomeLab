#!/usr/bin/env python3
"""Memory-bounded STREAMING restore of a VulnOps gzip-JSON backup.

The web/UI restore path (backup.restore_from_path) loads the whole archive into
memory at once -- fine for small DBs, but a large backup (hundreds of MB of JSON)
OOM-kills the container. This is the restore counterpart to the streaming BACKUP:
it scans the archive one document at a time, so peak memory is ~one insert batch
regardless of DB size.

Uses SYNC pymongo on purpose -- a one-off migration tool, no event loop, no motor
cross-loop pitfalls. Reads MONGO_URL / DB_NAME from the environment (present in the
backend and worker containers).

Archive format (see backup._stream_gzip_dump):
    {"created_at": <val>, "collections": {"name": [doc, doc, ...], ...}}
every doc/value emitted by bson.json_util.dumps (MongoDB Extended JSON).

Usage:
    python stream_restore.py /app/backups/RESTORE.json.gz [--keep]
      --keep : insert without dropping existing collections first (default: drop
               each collection before restoring it, matching a full restore).
"""
import gzip
import io
import os
import sys
from bson import json_util

BATCH = 1000


class _Reader:
    """Forward-only character reader over a text stream with a bounded buffer."""
    def __init__(self, textio, chunk=1 << 16):
        self._io = textio
        self._chunk = chunk
        self._buf = ""
        self._pos = 0

    def _fill(self):
        if self._pos:
            self._buf = self._buf[self._pos:]
            self._pos = 0
        more = self._io.read(self._chunk)
        if more:
            self._buf += more
            return True
        return False

    def peek(self):
        while self._pos >= len(self._buf):
            if not self._fill():
                return ""
        return self._buf[self._pos]

    def getc(self):
        c = self.peek()
        if c:
            self._pos += 1
        return c

    def skipws(self):
        while True:
            c = self.peek()
            if c and c in " \t\r\n":
                self._pos += 1
            else:
                return

    def expect(self, ch):
        self.skipws()
        c = self.getc()
        if c != ch:
            raise ValueError(f"expected {ch!r}, got {c!r}")

    def read_string(self):
        """Read a JSON string; returns the raw text INCLUDING surrounding quotes."""
        self.skipws()
        if self.getc() != '"':
            raise ValueError("expected string")
        out = ['"']
        while True:
            c = self.getc()
            if c == "":
                raise ValueError("EOF in string")
            out.append(c)
            if c == "\\":
                out.append(self.getc())
            elif c == '"':
                break
        return "".join(out)

    def read_value_raw(self):
        """Read one JSON value (object/array/scalar) and return its raw text."""
        self.skipws()
        c = self.peek()
        if c in "{[":
            return self._read_container()
        if c == '"':
            return self.read_string()
        out = []
        while True:
            ch = self.peek()
            if ch == "" or ch in ",}] \t\r\n":
                break
            out.append(self.getc())
        return "".join(out)

    def _read_container(self):
        out = []
        depth = 0
        instr = False
        esc = False
        while True:
            ch = self.getc()
            if ch == "":
                raise ValueError("EOF in container")
            out.append(ch)
            if instr:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    instr = False
                continue
            if ch == '"':
                instr = True
            elif ch in "{[":
                depth += 1
            elif ch in "}]":
                depth -= 1
                if depth == 0:
                    break
        return "".join(out)


def stream_docs(fileobj):
    """Yield (collection_name, doc_dict) from a gzip archive fileobj, one doc at a
    time, without materializing the whole archive."""
    text = io.TextIOWrapper(fileobj, encoding="utf-8")
    r = _Reader(text)
    r.expect("{")
    while True:
        r.skipws()
        if r.peek() == "}":
            r.getc()
            return
        key = json_util.loads(r.read_string())
        r.expect(":")
        if key != "collections":
            r.read_value_raw()  # e.g. created_at -- skip
        else:
            r.expect("{")
            while True:
                r.skipws()
                if r.peek() == "}":
                    r.getc()
                    break
                name = json_util.loads(r.read_string())
                r.expect(":")
                r.expect("[")
                while True:
                    r.skipws()
                    if r.peek() == "]":
                        r.getc()
                        break
                    raw = r.read_value_raw()
                    yield name, json_util.loads(raw)
                    r.skipws()
                    if r.peek() == ",":
                        r.getc()
                r.skipws()
                if r.peek() == ",":
                    r.getc()
        r.skipws()
        if r.peek() == ",":
            r.getc()


def main(argv):
    if len(argv) < 2:
        print("usage: stream_restore.py <archive.json.gz> [--keep]", file=sys.stderr)
        return 2
    path = argv[1]
    keep = "--keep" in argv[2:]
    from pymongo import MongoClient
    client = MongoClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]

    dropped = set()
    batches = {}
    counts = {}
    total = 0

    def flush(name):
        docs = batches.get(name)
        if docs:
            db[name].insert_many(docs, ordered=False)
            counts[name] = counts.get(name, 0) + len(docs)
            docs.clear()

    with open(path, "rb") as fh:
        gz = gzip.GzipFile(fileobj=fh, mode="rb")
        for name, doc in stream_docs(gz):
            if not keep and name not in dropped:
                db[name].drop()
                dropped.add(name)
            batches.setdefault(name, []).append(doc)
            total += 1
            if len(batches[name]) >= BATCH:
                flush(name)
            if total % 10000 == 0:
                print(f"  ...{total} docs", flush=True)
    for name in list(batches):
        flush(name)

    print("RESTORE OK")
    for name in sorted(counts):
        print(f"  {name}: {counts[name]}")
    print(f"  TOTAL: {total} documents across {len(counts)} collections")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
