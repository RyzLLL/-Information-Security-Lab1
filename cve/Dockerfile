# ---------------------------------------------------------------------------
# Nacos -- CVE-2021-29441 (authentication bypass via a spoofed User-Agent)
#
# The Vulhub image (vulhub/nacos:1.4.0) ships with
#     nacos.core.auth.enabled=false
# so everything is reachable there simply because nobody is authenticating --
# that is not the CVE. To demonstrate the real flaw authentication must be ON:
# a plain request is then rejected with 403, while a request carrying
#     User-Agent: Nacos-Server
# is treated as internal server-to-server traffic and skips the auth filter.
#
# Note on the fix (see Dockerfile.fixed): 1.4.1 only *introduces* the switch
#     nacos.core.auth.enable.userAgentAuthWhite
# and ships it as **true** for backwards compatibility, so upgrading alone does
# not stop the bypass -- the switch has to be turned off as well. We verified
# both: 1.4.1 with the default still leaks, 1.4.1 with it disabled returns 403.
# ---------------------------------------------------------------------------
FROM eclipse-temurin:8-jre

LABEL maintainer="lab1-secure-api" \
      description="Nacos with authentication enabled (CVE-2021-29441 lab)"

ARG NACOS_VERSION=1.4.0
ARG USER_AGENT_AUTH_WHITE=true

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    curl -fsSL -o /tmp/nacos.tar.gz \
        "https://github.com/alibaba/nacos/releases/download/${NACOS_VERSION}/nacos-server-${NACOS_VERSION}.tar.gz"; \
    mkdir -p /opt; \
    tar -xzf /tmp/nacos.tar.gz -C /opt; \
    rm /tmp/nacos.tar.gz; \
    CONF=/opt/nacos/conf/application.properties; \
    # authentication ON -- this is what makes the bypass meaningful
    sed -i 's/^nacos.core.auth.enabled=.*/nacos.core.auth.enabled=true/' "$CONF"; \
    # 1.4.1+ only: control the hard-coded User-Agent whitelist
    if grep -q '^nacos.core.auth.enable.userAgentAuthWhite=' "$CONF"; then \
        sed -i "s/^nacos.core.auth.enable.userAgentAuthWhite=.*/nacos.core.auth.enable.userAgentAuthWhite=${USER_AGENT_AUTH_WHITE}/" "$CONF"; \
    else \
        echo "nacos.core.auth.enable.userAgentAuthWhite=${USER_AGENT_AUTH_WHITE}" >> "$CONF"; \
    fi; \
    grep '^nacos.core.auth' "$CONF"

WORKDIR /opt/nacos
EXPOSE 8848
# The 1.4.x startup.sh forks java into the background and returns, which would
# stop the container; keep the log in the foreground so the container stays up.
CMD ["sh", "-c", "/opt/nacos/bin/startup.sh -m standalone && tail -f /opt/nacos/logs/start.out"]
