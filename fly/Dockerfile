# Use the official uv image with Python 3.13 preinstalled
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

WORKDIR /app

# Install dependencies. The wheels/ dir must be copied before uv sync because
# the lockfile references the datasette-accounts wheel by path.
COPY pyproject.toml uv.lock ./
COPY wheels wheels
RUN uv sync --locked --no-dev

# The rest: run.sh + the plugins/ dir with the sample providers
COPY . .

# Datasette must bind to 0.0.0.0 to be reachable outside the container
ENV PORT=8080
EXPOSE 8080

CMD ["./run.sh"]
