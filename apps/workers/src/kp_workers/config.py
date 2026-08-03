from pydantic_settings import BaseSettings, SettingsConfigDict


class WorkerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KP_WORKER_", env_file=".env", extra="ignore")

    worker_name: str = "worker"
    database_url: str = "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher"
    audit_database_url: str = "postgresql+psycopg://audit_writer:audit_writer@localhost:5432/kingphisher"
    audit_hmac_key: str = ""
    ciphertext_kek: str = ""
    redis_url: str = "redis://localhost:6379/0"
    queue_prefix: str = "kp:queue:"
    poll_seconds: int = 5
    log_level: str = "info"
    mock_graph_url: str = "http://localhost:8181"
    mock_ai_url: str = "http://localhost:8282"
    mailpit_smtp: str = "localhost:1025"
    tracking_base_url: str = "http://localhost:8001"
    training_base_url: str = "http://localhost:3000/training/awareness"
    training_domains: str = "example.com,training.local"

    def require_hmac(self) -> bytes:
        if not self.audit_hmac_key:
            raise RuntimeError("KP_WORKER_AUDIT_HMAC_KEY is required")
        return self.audit_hmac_key.encode()

    def require_kek(self) -> bytes:
        if not self.ciphertext_kek:
            raise RuntimeError("KP_WORKER_CIPHERTEXT_KEK is required")
        return self.ciphertext_kek.encode()

    def training_domain_set(self) -> set[str]:
        return {d.strip().lower() for d in self.training_domains.split(",") if d.strip()}
