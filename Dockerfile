FROM python:3.12-slim

WORKDIR /app

# Install dependencies first for layer caching
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Copy application code
COPY tvm_core/ tvm_core/
COPY x402_tvm/ x402_tvm/
COPY facilitator/ facilitator/

EXPOSE 8402

CMD ["uvicorn", "facilitator.main:app", "--host", "0.0.0.0", "--port", "8402"]
