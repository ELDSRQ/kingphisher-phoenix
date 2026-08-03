import os

os.environ.setdefault("OPERATOR_API_AUDIT_HMAC_KEY",
                      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
os.environ.setdefault("OPERATOR_API_CIPHERTEXT_KEK", "0123456789abcdef0123456789abcdef")
