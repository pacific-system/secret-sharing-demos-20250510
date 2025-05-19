#!/bin/bash

# Script to set up GitHub MCP server globally

echo "Setting up GitHub MCP server globally..."

# Change to the GitHub MCP server directory
cd "$(dirname "$0")/servers/src/github"

# Install dependencies if needed
echo "Installing dependencies..."
npm install

# Build the server
echo "Building the server..."
npm run build

# Create a global symlink
echo "Creating global symlink..."
npm link

echo ""
echo "GitHub MCP server has been set up globally."
echo "You can now run it from anywhere using the following command:"
echo "GITHUB_PERSONAL_ACCESS_TOKEN=your_token mcp-server-github"
echo ""
echo "To create a GitHub Personal Access Token, visit:"
echo "https://github.com/settings/tokens"
echo "Make sure to grant 'repo' scope (Full control of private repositories)."
echo ""
echo "Alternatively, you can use the start_github_mcp.sh script:"
echo "export GITHUB_PERSONAL_ACCESS_TOKEN=your_token"
echo "./start_github_mcp.sh"