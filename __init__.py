# SOAR MCP Server
# Copyright 2026 Andreas Buis
#
# Exposes Splunk SOAR as an MCP server endpoint.
# MCP handler:    soar_mcp_handler.SoarMcpRestHandler
# Config file:    local/mcp.conf  (override default/mcp.conf)
# Token store:    local/mcp_tokens.json  (v1.5.0+, scoped MCP tokens)
# MCP endpoint:   https://<soar>/rest/handler/phantom_soar_mcp_server/mcp
