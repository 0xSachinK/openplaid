# Pass an immutable reviewed python:3.11-slim-bookworm digest; no default mutable base.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /opt/openplaid
COPY verification/requirements.lock /tmp/requirements.lock
COPY verification/requirements-sandbox.lock /tmp/requirements-sandbox.lock
RUN pip install --no-cache-dir --no-compile -r /tmp/requirements.lock -r /tmp/requirements-sandbox.lock
COPY verification /opt/openplaid/verification
# Normalize installation/source mtimes as well as disabling timestamped pip bytecode.
RUN find /usr/local /opt /tmp -exec touch -h -d @0 {} +
# Nitro bootstrap does not preserve Docker's PATH/WORKDIR assumptions.
ENTRYPOINT ["/usr/local/bin/python", "/opt/openplaid/verification/boot.py"]
