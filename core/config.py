from pydantic_settings import BaseSettings

class Settings(BaseSettings):
   
    # db
    mariadb_url: str

    secret_key: str
    algorithm: str

    analyzer_base_url: str
    class Config:
        env_file = ".env" # 이 클래스가 실행될 때 .env 파일을 읽어오라고 지시

# 이 settings 객체 하나만 임포트하면 프로젝트 어디서든 환경변수를 꺼내 쓸 수 있습니다.
settings = Settings()