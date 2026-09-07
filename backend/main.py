"""
main.py — FastAPI application.

Defines a single POST /check endpoint that ties together:
  - Layer 2 (Feature Extraction): features.py -> extract_features()
  - Layer 3 (Model Inference):    model.pkl (RandomForestClassifier)
  - Layer 4 (Response):           probability -> score/level/explanation

The model is loaded once at startup (not per-request) for performance.
"""

import os

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import joblib

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from features import extract_features, FEATURE_NAMES

MODEL_PATH = "model.pkl"

app = FastAPI(title="RiskLens API")

# Rate limiting: caps how many requests a single visitor (identified by
# IP address) can make per minute. This protects the backend from being
# hammered directly (e.g. a script bypassing the website entirely and
# calling /check thousands of times), which the frontend alone can never
# prevent since it can always be skipped.
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Allow the frontend (running on a different origin) to call this API.
#
# FRONTEND_URL must be set in Render's environment settings to the deployed
# frontend origin (e.g. https://your-frontend.onrender.com). Comma-separated
# values are accepted if more than one origin needs to call this API.
# Locally we fall back to the Vite dev server so CORS works with zero setup.
#
# allow_credentials=False because this API takes no cookies/auth headers;
# note that allow_origins=["*"] and allow_credentials=True can never be
# combined (browsers reject that combination outright), so if credentials
# are ever needed later, ALLOWED_ORIGINS must list explicit origins, never "*".
_DEFAULT_FRONTEND_ORIGIN = "http://localhost:5173"
_frontend_url = os.getenv("FRONTEND_URL", _DEFAULT_FRONTEND_ORIGIN)
ALLOWED_ORIGINS = [origin.strip() for origin in _frontend_url.split(",") if origin.strip()]
if not ALLOWED_ORIGINS:
    ALLOWED_ORIGINS = [_DEFAULT_FRONTEND_ORIGIN]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["Content-Type"],
)

# POST /check only needs a short JSON body ({"url": "..."}). Cap the raw
# request size so a huge payload is rejected before JSON parsing/validation.
MAX_CHECK_BODY_BYTES = 10 * 1024  # 10KB


@app.middleware("http")
async def limit_check_body_size(request: Request, call_next):
    if request.method == "POST" and request.url.path == "/check":
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                declared_size = int(content_length)
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid Content-Length header."},
                )
            if declared_size > MAX_CHECK_BODY_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request body too large."},
                )
    return await call_next(request)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# Loaded once at startup, reused across all requests.
model = joblib.load(MODEL_PATH)


class URLRequest(BaseModel):
    url: str


class CheckResponse(BaseModel):
    url: str
    score: int
    level: str
    explanation: list[str]


# Human-readable explanation text for each feature, shown only when
# that feature "fired" (i.e. indicates risk) for a given URL.
FEATURE_EXPLANATIONS = {
    "url_length": "The URL is unusually long, which can be used to hide the real destination.",
    "num_dots": "The URL contains an unusually high number of dots.",
    "has_at_symbol": "The URL contains an '@' symbol, which can be used to disguise the true destination.",
    "has_hyphen_in_domain": "The domain contains hyphens, often used to mimic a trusted brand name.",
    "is_ip_address": "The URL uses a raw IP address instead of a domain name.",
    "is_https": "The URL does not use HTTPS, which is common in phishing pages.",
    "num_subdomains": "The URL has an unusually high number of subdomains.",
    "has_suspicious_keyword": "The URL contains a keyword commonly used in phishing attempts (e.g. 'login', 'verify', 'secure').",
    "num_digits": "The URL contains an unusually high number of digits.",
    "is_shortened_url": "The URL uses a known link-shortening service, which can hide the real destination.",
}

# Thresholds used to flag a feature as "contributing to risk" for the
# explanation list. Booleans (0/1 flags) fire whenever they're 1; counts
# fire only past a reasonable threshold so normal URLs don't get flagged
# for e.g. having a couple of dots.
FEATURE_RISK_THRESHOLDS = {
    "url_length": 75,
    "num_dots": 4,
    "has_at_symbol": 1,
    "has_hyphen_in_domain": 1,
    "is_ip_address": 1,
    "is_https": 0,  # fires when is_https == 0 (i.e. NOT https)
    "num_subdomains": 3,
    "has_suspicious_keyword": 1,
    "num_digits": 8,
    "is_shortened_url": 1,
}


def build_explanation(feature_values: list) -> list[str]:
    """Builds a list of human-readable reasons based on which features fired."""
    reasons = []
    feature_map = dict(zip(FEATURE_NAMES, feature_values))

    for name, value in feature_map.items():
        threshold = FEATURE_RISK_THRESHOLDS[name]
        fired = (value == 0) if name == "is_https" else (value >= threshold)
        if fired:
            reasons.append(FEATURE_EXPLANATIONS[name])

    return reasons


def probability_to_score(phishing_probability: float) -> int:
    """Converts a 0.0-1.0 phishing probability into a 0-5 integer score."""
    score = round(phishing_probability * 5)
    return max(0, min(5, score))


def score_to_level(score: int) -> str:
    """Maps a 0-5 score into a human-readable risk level."""
    if score <= 1:
        return "Safe"
    if score <= 3:
        return "Suspicious"
    return "Dangerous"


@app.post("/check", response_model=CheckResponse)
@limiter.limit("10/minute")
def check_url(request: Request, body: URLRequest):
    url = body.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL must not be empty.")

    if len(url) > 2048:
        raise HTTPException(status_code=400, detail="URL is too long.")

    # Layer 2: Feature Extraction
    feature_values = extract_features(url)

    # Layer 3: Model Inference
    # predict_proba returns [[prob_class_0, prob_class_1]]; class 1 = phishing.
    try:
        phishing_probability = model.predict_proba([feature_values])[0][1]
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Something went wrong processing this URL.",
        )

    # Layer 4: Response building
    score = probability_to_score(phishing_probability)
    level = score_to_level(score)
    explanation = build_explanation(feature_values)

    if not explanation:
        explanation = ["No obvious risk indicators were found in this URL."]

    return CheckResponse(
        url=url,
        score=score,
        level=level,
        explanation=explanation,
    )


@app.get("/")
def root():
    return {"status": "RiskLens API is running", "endpoint": "POST /check"}
    