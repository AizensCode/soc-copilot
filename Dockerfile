# The watch loop's container. Design constraints, in order:
#
# - The app resolves its grounding data (data/asset_context.json,
#   data/sigma/, data/mitre/, data/phishing/) relative to the CWD or the
#   package's parent, so the image carries the repo layout at /app and
#   runs from there — NOT a bare wheel install, which would strand the
#   data outside site-packages.
# - Runs as a non-root user. The only thing it may write is data/
#   (the append-only history store); the venv and code stay read-only.
# - Secrets never enter the image: .env is dockerignored and supplied at
#   run time (compose `env_file:`, or -e flags). So is data/history/ —
#   a dev machine's real investigation records must not ship in layers.
# - uv with the committed lockfile, so the container runs the exact
#   dependency set CI tested.
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /usr/local/bin/uv

RUN useradd --create-home --uid 10001 copilot

WORKDIR /app

# Dependencies first, so code edits don't re-resolve the world.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY README.md ./
COPY soc_copilot/ soc_copilot/
COPY data/ data/
RUN uv sync --frozen --no-dev \
    && mkdir -p data/history \
    && chown -R copilot:copilot /app/data

USER copilot
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["soc-copilot"]
# The flagship mode; override the command for one-shot runs
# (e.g. `docker run ... soc-copilot-image --scorecard`).
CMD ["--watch", "60"]
