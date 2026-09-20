"""Password hashing: round-trip, wrong-password rejection, and the bcrypt 72-byte
guard (bcrypt 4.x raises on >72-byte input instead of truncating). Also confirms an
existing stored bcrypt hash still verifies after the refactor (no forced resets)."""
import os, sys
os.environ.update(MONGO_URL="x", DB_NAME="t", JWT_SECRET="x")
sys.path.insert(0, ".")
import bcrypt
import auth_utils as au
def a(c,m=""): assert c,m

h = au.hash_password("correct horse battery staple")
a(au.verify_password("correct horse battery staple", h), "round-trip verify")
a(not au.verify_password("wrong", h), "wrong password rejected")
print("PASS: hash/verify round-trip + wrong-password rejection")

# >72 bytes must not raise (the bcrypt 4.x failure mode) and must verify
long_pw = "A" * 200
hl = au.hash_password(long_pw)
a(au.verify_password(long_pw, hl), "long password hashes+verifies without raising")
# first-72-bytes semantics: differs only past byte 72
a(au.verify_password("A"*72 + "different tail", hl), "verify uses first 72 bytes (bcrypt semantics)")
print("PASS: 72-byte guard -- long passphrases don't 500, bcrypt semantics preserved")

# an existing hash created the OLD way (raw bcrypt on full bytes) still verifies
legacy = bcrypt.hashpw("legacyPass123".encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
a(au.verify_password("legacyPass123", legacy), "pre-existing stored hash still verifies")
print("PASS: existing stored hashes still verify (no forced password resets)")

a(not au.verify_password("x", ""), "empty/garbage hash returns False, not an exception")
print("PASS: malformed hash handled gracefully")

print("\nALL PASSWORD HASHING TESTS PASSED")
