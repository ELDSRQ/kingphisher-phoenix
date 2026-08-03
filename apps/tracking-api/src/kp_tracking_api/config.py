from pydantic_settings import BaseSettings, SettingsConfigDict


class TrackingApiSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TRACKING_API_", env_file=".env", extra="ignore")

    app_name: str = "kp-tracking-api"
    database_url: str = "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher"
    training_base_url: str = "http://localhost:3000"
    rate_limit_per_minute: int = 600
    log_level: str = "info"
