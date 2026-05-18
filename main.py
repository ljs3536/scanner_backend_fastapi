from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware # 추가!
from routers import auth, scan, sbom, llm, admin, ai
import models
from database import engine

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Scanner Demo API")

# --- CORS 설정 추가 ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000","http://192.168.1.103:3000"], # Next.js 포트 허용
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# ----------------------

app.include_router(auth.router)
app.include_router(scan.router)
app.include_router(sbom.router)
app.include_router(llm.router)
app.include_router(admin.router)
app.include_router(ai.router)
@app.get("/")
def read_root():
    return {"message": "Scanner API Server is running."}