FROM splunk/splunk:10.2

USER root

# Pre-install MCP Server app
COPY apps/Splunk_MCP_Server /opt/splunk/etc/apps/Splunk_MCP_Server

# Copy setup and seed scripts
COPY scripts/setup.sh /setup.sh
COPY scripts/seed.sh /seed.sh

# Copy sample data
COPY sample-data/auth.log /sample-data/auth.log
COPY sample-data/attack.log /sample-data/attack.log

RUN chmod +x /setup.sh /seed.sh && \
    chown -R splunk:splunk /opt/splunk/etc/apps/Splunk_MCP_Server && \
    chown splunk:splunk /setup.sh /seed.sh && \
    chown -R splunk:splunk /sample-data

# Don't override entrypoint — use official one
# Setup runs via docker exec after container is healthy
# Disable Splunk web UI — only management port (8089) needed for MCP
RUN mkdir -p /opt/splunk/etc/system/local && \
    echo -e "[settings]\nstartwebserver = false" > /opt/splunk/etc/system/local/web.conf
