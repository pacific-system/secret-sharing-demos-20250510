# GitHub MCP Server Setup Guide

This guide explains how to set up and use the GitHub Model Context Protocol (MCP) server globally on your system. The MCP server allows AI assistants to interact with GitHub repositories through the GitHub API.

## Prerequisites

- Node.js (v14 or later)
- npm (v6 or later)
- A GitHub account and Personal Access Token

## Setup Instructions

### 1. Create a GitHub Personal Access Token

1. Go to [GitHub Personal Access Tokens](https://github.com/settings/tokens)
2. Click "Generate new token"
3. Give your token a name (e.g., "MCP Server")
4. Select the `repo` scope (Full control of private repositories)
   - If working only with public repositories, select only the `public_repo` scope
5. Click "Generate token"
6. **Copy the token** - you will need it later and won't be able to see it again

### 2. Install the MCP Server Globally

Run the setup script to install the GitHub MCP server globally:

```bash
./setup_github_mcp_global.sh
```

This script will:

- Install dependencies
- Build the server
- Create a global symlink so you can run the server from anywhere

### 3. Run the MCP Server

You can run the server in two ways:

#### Option 1: Using the start script

```bash
export GITHUB_PERSONAL_ACCESS_TOKEN=your_token_here
./start_github_mcp.sh
```

#### Option 2: Run directly from any directory

```bash
GITHUB_PERSONAL_ACCESS_TOKEN=your_token_here mcp-server-github
```

### 4. VS Code Integration

To integrate with VS Code, add the MCP configuration to your User Settings:

1. Press `Ctrl + Shift + P` and type `Preferences: Open User Settings (JSON)`
2. Add the configuration from `vscode_mcp_config.json` to your settings file

Alternatively, you can create a `.vscode/mcp.json` file in your workspace:

1. Create a `.vscode` directory in your project (if it doesn't exist)
2. Copy the contents of `vscode_mcp_config.json` to `.vscode/mcp.json`

## Using the MCP Server

Once the server is running, it provides access to the following GitHub features:

- Repository management
- File operations
- Code search
- Issues and Pull Requests
- And more

AI assistants that support the Model Context Protocol (like Claude) can now interact with your GitHub repositories through natural language.

## Troubleshooting

### The server isn't starting

- Make sure you've set the `GITHUB_PERSONAL_ACCESS_TOKEN` environment variable
- Check that Node.js is installed and in your PATH
- Verify that the installation was successful with `which mcp-server-github`

### Authentication errors

- Make sure your GitHub token is valid and has the correct permissions
- Verify that you can access the GitHub API with your token using curl:
  ```bash
  curl -H "Authorization: token YOUR_TOKEN" https://api.github.com/user
  ```

### MCP client can't connect to the server

- Ensure the server is running before connecting your MCP client
- Check if another process is using the same port

## Resources

- [GitHub MCP Server Documentation](https://github.com/modelcontextprotocol/servers/tree/main/src/github)
- [Model Context Protocol](https://modelcontextprotocol.io)
- [GitHub API Documentation](https://docs.github.com/en/rest)
