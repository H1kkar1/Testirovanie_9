from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import BaseModel
from pydantic import PostgresDsn


class JWTSettings(BaseModel):
    secret: str
    algorithm: str
    access_token_expire_minutes: int


class DbSettings(BaseModel):
    url: PostgresDsn
    echo: bool = True
    echo_pool: bool = False
    pool_size: int = 50
    max_overflow: int = 10


class RunSettings(BaseModel):
    host: str = "localhost"
    port: int = 8001
    reload: bool = True


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file="app/.env",
        case_sensitive=False,
        env_nested_delimiter="__",
    )
    run: RunSettings = RunSettings()
    db: DbSettings
    jwt: JWTSettings


settings = Settings()
