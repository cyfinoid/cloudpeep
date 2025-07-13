#!/bin/bash

# PeekInTheCloud Deployment Script
# This script copies all necessary files to the docs folder for deployment

echo "🚀 Starting PeekInTheCloud deployment..."

# Create docs directory if it doesn't exist
mkdir -p docs

# Copy main application files
echo "📁 Copying main application files..."
cp index.html docs/
cp style.css docs/
cp -r js docs/
cp -r icons docs/

# Copy any additional assets
echo "🎨 Copying additional assets..."
if [ -d "assets" ]; then
    cp -r assets docs/
fi

# Create .nojekyll file for GitHub Pages
echo "🔧 Creating .nojekyll file for GitHub Pages compatibility..."
touch docs/.nojekyll

# Verify deployment
echo "🔍 Verifying deployment..."
if [ -f "docs/index.html" ] && [ -f "docs/js/app.js" ] && [ -f "docs/.nojekyll" ]; then
    echo "✅ Deployment successful!"
    echo "📊 Deployment summary:"
    echo "   - Main application: ✅"
    echo "   - JavaScript modules: ✅"
    echo "   - Assets: ✅"
    echo "   - GitHub Pages compatibility: ✅"
    echo ""
    echo "🌐 Ready for deployment to:"
    echo "   - GitHub Pages"
    echo "   - Netlify"
    echo "   - Vercel"
    echo "   - Any static hosting service"
    echo ""
    echo "📁 Deployment folder: docs/"
else
    echo "❌ Deployment failed - missing critical files"
    exit 1
fi

echo ""
echo "🎉 PeekInTheCloud deployment completed successfully!"
echo "📁 All files copied to: docs/"
echo "🚀 Ready for deployment to any static hosting service" 