# Pass an immutable reviewed python:3.11-slim-bookworm digest; no default mutable base.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /opt/openplaid
COPY verification/requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir -r /tmp/requirements.lock
COPY verification /opt/openplaid/verification
# Nitro bootstrap does not preserve Docker's PATH/WORKDIR assumptions.
ENTRYPOINT ["/usr/local/bin/python", "/opt/openplaid/verification/boot.py"]
