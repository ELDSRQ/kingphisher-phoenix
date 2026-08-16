from pydantic_settings import BaseSettings, SettingsConfigDict


class TrackingApiSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TRACKING_API_", env_file=".env", extra="ignore")

    app_name: str = "kp-tracking-api"
    host: str = "127.0.0.1"
    port: int = 8001
    database_url: str = "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher"
    training_base_url: str = "http://localhost:3000"
    rate_limit_ip_per_min: int = 60
    rate_limit_token_per_min: int = 5
    rate_limit_global_per_min: int = 3000
    rate_limit_max_keys: int = 10_000
    corrections_secret: str = ""
    trusted_proxies: str = ""
    log_level: str = "info"
