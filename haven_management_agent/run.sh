#!/usr/bin/with-contenv bashio
set -eu

cd /opt/haven-agent
exec python3 -B -m haven_management_agent.server
