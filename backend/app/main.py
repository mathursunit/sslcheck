from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from .utils.ssl_checker import SSLChecker

app = FastAPI(title="SSLCheck API")

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict this to your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class CheckRequest(BaseModel):
    hostname: str

@app.get("/")
async def root():
    return {"status": "online", "message": "SSLCheck API is running"}

@app.post("/check")
async def check_ssl(request: CheckRequest):
    hostname = request.hostname.strip().lower()
    if not hostname:
        raise HTTPException(status_code=400, detail="Hostname is required")
    
    # Simple validation to remove protocol if present
    if "://" in hostname:
        hostname = hostname.split("://")[-1]
    if "/" in hostname:
        hostname = hostname.split("/")[0]

    checker = SSLChecker(hostname)
    result = checker.get_cert_details()
    
    if "error" in result:
        print(f"SSL Check Error for {hostname}: {result['error']}")
        raise HTTPException(status_code=400, detail=result["error"])
    
    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
