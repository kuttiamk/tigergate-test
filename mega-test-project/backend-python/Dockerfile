# =============================================================================
# backend-python/Dockerfile
# =============================================================================
# PURPOSE: Builds the Python Flask API server.
#
# ⚠️  INTENTIONAL ISSUES IN THIS FILE:
#   1. BAD: python:3.9 (not slim) — large image, more attack surface
#   2. BAD: Running as root
#   3. BAD: No multi-stage build — dev tools included in production image
#   4. BAD: FLASK_DEBUG=1 re-enabled as CMD arg
# =============================================================================

# BAD: Should use python:3.11-slim-bullseye
FROM python:3.9

WORKDIR /app

COPY requirements.txt .

# BAD: --no-cache-dir not used — pip cache bloats image
RUN pip install -r requirements.txt

COPY . .

EXPOSE 5000

# BAD: Debug mode enabled — exposes Werkzeug interactive debugger
CMD ["python", "app.py"]
