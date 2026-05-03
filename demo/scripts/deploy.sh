#!/bin/bash
API_KEY="sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEF"
DB_PASS="supersecretpassword123"
aws s3 sync ./dist s3://my-prod-bucket --region us-east-1
