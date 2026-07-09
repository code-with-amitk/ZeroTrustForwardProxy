# syntax=docker/dockerfile:1

FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY api/ api/
COPY policy_compiler/ policy_compiler/
COPY schema/ schema/
COPY pytest.ini .

ENV ZTFP_POLICY_DIR=/var/ztfp/policies
ENV CONTROL_PLANE_HOST=0.0.0.0
ENV CONTROL_PLANE_PORT=8090

RUN mkdir -p /var/ztfp/policies

EXPOSE 8090

CMD ["python", "-m", "api.server"]
