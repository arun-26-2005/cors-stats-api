import time
import uuid
import logging
from fastapi import FastAPI, Request, Response, Query
from fastapi.responses import JSONResponse

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="CORS-Aware Metrics API")

ALLOWED_ORIGIN = "https://dash-m7zybj.example.com"
MY_EMAIL = "23f2001194@ds.study.iitm.ac.in"

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
            response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
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
