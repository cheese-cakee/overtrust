#!/bin/bash
# Deployment script (demo — all values are fake placeholders)

API_KEY=sk_DEMO_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
SECRET_TOKEN=ghp_DEMO_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

export AWS_SECRET_ACCESS_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

echo "Deploying..."
curl -H "Authorization: Bearer $API_KEY" https://api.example.com/deploy
