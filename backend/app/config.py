from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent  # repo root


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=BASE_DIR / ".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "CyberLabs"
    data_dir: Path = BASE_DIR / "data"
    labs_dir: Path = BASE_DIR / "labs"
    generated_dir: Path = BASE_DIR / "labs" / "generated"
    db_file: Path = BASE_DIR / "data" / "cyberlabs.db"

    # AI provider (OpenAI-compatible). If key is empty, only default labs work.
    ai_api_key: str = ""
    ai_base_url: str = "https://api.openai.com/v1"
    ai_model: str = "gpt-4o-mini"
    ai_timeout_seconds: int = 120

    # Lab sandbox / lifecycle
    lab_ttl_minutes: int = 60
    max_concurrent_labs: int = 3
    mem_limit: str = "256m"
    cpu_nano: int = 500_000_000  # 0.5 core
    pids_limit: int = 128
    image_prefix: str = "cyberlabs"
    build_platform: str = "linux/amd64"
    network_name: str = "cyberlabs-net"
    build_timeout_seconds: int = 300
    health_check_seconds: int = 30

    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    def ensure_dirs(self) -> None:
        (self.data_dir).mkdir(parents=True, exist_ok=True)
        (self.generated_dir).mkdir(parents=True, exist_ok=True)


settings = Settings()