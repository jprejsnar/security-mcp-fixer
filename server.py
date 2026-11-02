"""Run the GitLab security MCP server over stdio.

Cursor launches this file as a subprocess. stdout is the MCP protocol,
so this module prints nothing at import time.
"""

from gitlab_security_mcp.server import main, mcp

__all__ = ["main", "mcp"]

if __name__ == "__main__":
    main()
