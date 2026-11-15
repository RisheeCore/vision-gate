FROM python:3.12-slim
# Stdlib only; remove package managers to eliminate in-container install surface
RUN python -m pip uninstall -y pip setuptools wheel || true
USER 65534:65534
WORKDIR /tmp
