#!/bin/bash
# Jarwis Deployment Script (Bash)
# Unified deployment pipeline for Linux/Mac

set -e

ENVIRONMENT="${1:-development}"
SKIP_TESTS="${2:-false}"

echo "🚀 Jarwis Deployment Pipeline"
echo "=============================="
echo ""

# Step 1: Run deployment gateway
echo "📋 Step 1: Validating system..."

GATEWAY_ARGS="deploy_gateway.py --env $ENVIRONMENT"
if [ "$SKIP_TESTS" = "true" ]; then
    GATEWAY_ARGS="$GATEWAY_ARGS --skip-tests"
fi

python $GATEWAY_ARGS

if [ $? -ne 0 ]; then
    echo "❌ Deployment validation failed!"
    exit 1
fi

echo ""
echo "✅ Deployment validation passed!"
echo ""

# Step 2: Deploy based on environment
if [ "$ENVIRONMENT" = "production" ]; then
    echo "🐳 Step 2: Building Docker images..."
    docker-compose build --no-cache
    
    # Tag images with git SHA
    GIT_SHA=$(git rev-parse --short HEAD)
    echo "🏷️  Tagging images with SHA: $GIT_SHA"
    docker tag jarwis-backend:latest "jarwis-backend:$GIT_SHA"
    docker tag jarwis-frontend:latest "jarwis-frontend:$GIT_SHA"
    
    echo ""
    echo "🛑 Step 3: Stopping old containers..."
    docker-compose down
    
    echo ""
    echo "▶️  Step 4: Starting new containers..."
    docker-compose up -d
    
    echo ""
    echo "⏳ Waiting for services..."
    sleep 15
    
    echo ""
    echo "🏥 Step 5: Health check..."
    curl -f http://localhost/api/health || exit 1
    
    echo ""
    echo "✅ Deployment complete!"
    echo "🌐 Frontend: http://localhost"
    echo "🔌 Backend: http://localhost/api"
else
    echo "📋 Development Environment Ready!"
    echo ""
    echo "To start services:"
    echo "  1. Backend:  python -m uvicorn api.server:app --reload"
    echo "  2. Frontend: cd jarwisfrontend && npm start"
    echo ""
fi

echo ""
echo "✅ Deployment pipeline completed!"
