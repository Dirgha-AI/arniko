FROM node:20-alpine

WORKDIR /app

# Install security tools
RUN apk add --no-cache \
    python3 \
    py3-pip \
    git \
    curl \
    bash

# Copy package files
COPY package*.json ./
COPY pnpm-lock.yaml ./

# Install dependencies
RUN npm install -g pnpm
RUN pnpm install --production

# Copy built application
COPY dist/ ./dist/
COPY .env.example ./.env

# Expose port
EXPOSE 3010

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3010/health || exit 1

# Start server
CMD ["node", "dist/server.js"]
