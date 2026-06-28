FROM python:3.11-slim

# ── System packages ───────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        jq \
        unzip \
        procps \
        cron \
        git \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/*

# ── SnowSQL ───────────────────────────────────────────────────────────────────
# SNOWSQL_DEST + SNOWSQL_LOGIN_SHELL must be set before running the installer
# or it enters interactive mode and hangs the build.
ENV SNOWSQL_DEST=/usr/local/bin
ENV SNOWSQL_LOGIN_SHELL=/bin/bash

RUN curl -sfL \
        "https://sfc-repo.snowflakecomputing.com/snowsql/bootstrap/1.2/linux_x86_64/snowsql-1.2.32-linux_x86_64.bash" \
        -o /tmp/snowsql.bash \
    && bash /tmp/snowsql.bash \
    && rm /tmp/snowsql.bash

# SnowSQL expects ~/.snowsql/config to exist; actual connection params come
# from CLI args in stage_to_snowflake.sh, not this file.
RUN mkdir -p /root/.snowsql \
    && printf '[connections]\naccountname=placeholder\n' > /root/.snowsql/config

# ── dbt ───────────────────────────────────────────────────────────────────────
RUN pip install --no-cache-dir "dbt-snowflake>=1.9,<2.0"

# ── bats-core (for bash unit tests) ──────────────────────────────────────────
RUN git clone --depth 1 https://github.com/bats-core/bats-core.git /tmp/bats-core \
    && cd /tmp/bats-core && ./install.sh /usr/local \
    && rm -rf /tmp/bats-core

# ── Non-root pipeline user ────────────────────────────────────────────────────
# The entrypoint still runs as root (to manage crond and write /etc/cron.d),
# but the cron job itself executes as cveuser so the pipeline process has no
# write access outside its designated directories.
RUN useradd -r -u 1001 -g root -s /bin/bash -m cveuser \
    && mkdir -p /home/cveuser/.snowsql \
    && cp /root/.snowsql/config /home/cveuser/.snowsql/config \
    && chown -R cveuser:root /home/cveuser/.snowsql \
    && chmod 600 /home/cveuser/.snowsql/config

# ── Project files ─────────────────────────────────────────────────────────────
WORKDIR /app

COPY scripts/   scripts/
COPY dbt/       dbt/
COPY sql/       sql/
COPY tests/     tests/
COPY config/    config/
COPY logs/.gitkeep logs/.gitkeep

RUN chmod +x scripts/*.sh \
    && chown -R cveuser:root /app

# ── Entrypoint ────────────────────────────────────────────────────────────────
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# tini (PID 1) handles signal forwarding and zombie reaping
ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
