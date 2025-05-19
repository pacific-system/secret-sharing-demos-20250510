#!/bin/bash

# Script to start GitHub MCP server globally

# Check if GitHub token is provided as an environment variable
if [ -z "$GITHUB_PERSONAL_ACCESS_TOKEN" ]; then
    echo "Please set the GITHUB_PERSONAL_ACCESS_TOKEN environment variable"
    echo "Example: export GITHUB_PERSONAL_ACCESS_TOKEN=your_token_here"
    exit 1
fi

# Change to the GitHub MCP server directory
cd "$(dirname "$0")/servers/src/github"

# Run the server
echo "Starting GitHub MCP server..."
node dist/index.js