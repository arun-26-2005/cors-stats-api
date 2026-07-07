import time
import uuid
import logging
import jwt
from fastapi import FastAPI, Request, Response, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="CORS-Aware Metrics API")

ALLOWED_ORIGIN = "https://dash-m7zybj.example.com"
MY_EMAIL = "23f2001194@ds.study.iitm.ac.in"

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2ok0HspNjga+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HcnpITcbWCSe1bvbYGuc3EbNy4xFyf5CbJ5DHJMID
Ekry0gyd2giIIIBOuBj8S63uGcnRp0Bh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyjJg2axVfmq7i6SuKr1JoWYG7xTTAKvPujsl40tsQf03h5NepzdfXpr28OnnzfW
ed+zcLR6BcmNNo/WvFj4xyCLSf0BC0gdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrBKR0NEbSQq4XkadEjsCs4F1Rncs4Llgnit7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

class TokenVerificationRequest(BaseModel):
    token: str

@app.middleware("http")
async def process_request(request: Request, call_next):
    start_time = time.time()
    
    # Generate request ID
    request_id = str(uuid.uuid4())
    
    # CORS Origin check
    origin = request.headers.get("Origin")
    
    # Preflight Check (OPTIONS)
    if request.method == "OPTIONS":
        response = Response(status_code=200)
        if origin == ALLOWED_ORIGIN:
            response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Request-ID, X-Process-Time"
            response.headers["Access-Control-Max-Age"] = "600"
        
        # Add required headers
        process_time = time.time() - start_time
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = f"{process_time:.6f}"
        return response
    
    # For actual request
    try:
        response = await call_next(request)
    except Exception as e:
        logger.error(f"Unhandled exception: {e}", exc_info=True)
        response = JSONResponse(
            status_code=500,
            content={"detail": "Internal Server Error"}
        )
    
    # Add CORS ACAO header for simple/actual requests if origin matches
    if origin == ALLOWED_ORIGIN:
        response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
        
    # Add required headers
    process_time = time.time() - start_time
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = f"{process_time:.6f}"
    
    return response

@app.get("/stats")
async def get_stats(values: str = Query(None)):
    if not values:
        return JSONResponse(
            status_code=400,
            content={"detail": "Missing query parameter 'values'"}
        )
    
    try:
        parts = values.split(",")
        int_vals = []
        for part in parts:
            part = part.strip()
            if part:
                int_vals.append(int(part))
        
        if not int_vals:
            return JSONResponse(
                status_code=400,
                content={"detail": "No valid integers provided"}
            )
            
        n = len(int_vals)
        s = sum(int_vals)
        m = min(int_vals)
        x = max(int_vals)
        mean = float(s) / n
        
        return {
            "email": MY_EMAIL,
            "count": n,
            "sum": s,
            "min": m,
            "max": x,
            "mean": mean
        }
    except ValueError:
        return JSONResponse(
            status_code=400,
            content={"detail": "Invalid integer values provided"}
        )

@app.post("/verify")
async def verify_token(req: TokenVerificationRequest):
    try:
        payload = jwt.decode(
            req.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            audience="tds-9is393ft.apps.exam.local",
            issuer="https://idp.exam.local"
        )
        return {
            "valid": True,
            "email": payload.get("email"),
            "sub": payload.get("sub"),
            "aud": payload.get("aud")
        }
    except jwt.PyJWTError as e:
        logger.info(f"Token verification failed: {e}")
        return JSONResponse(
            status_code=401,
            content={"valid": False}
        )
