FROM python:3.8.19-slim

ARG UID=10001
ARG GID=10001

# Create group and user in a single RUN command to reduce layers
RUN groupadd -g ${GID} app && \
    useradd -m -u ${UID} -g ${GID} -s /usr/sbin/nologin app && \
    mkdir /app && chown -R app:app /app

# Switch to the non-root user
USER app

WORKDIR /app

# Copy requirements and install dependencies
COPY --chown=app:app requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY --chown=app:app . .

CMD ["python", "lists2safebrowsing.py"]