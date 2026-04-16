from pathlib import Path

from pydantic import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    database_url: str = f"sqlite+aiosqlite:///{BASE_DIR / 'data' / 'soc.db'}"
    log_dir: str = str(BASE_DIR / 'logs')
    log_level: str = 'INFO'
    host: str = '0.0.0.0'
    port: int = 8000
    failed_login_threshold: int = 5
    failed_login_window_seconds: int = 120
    class Config:
        env_file = BASE_DIR / '.env'
        env_file_encoding = 'utf-8'


settings = Settings()
