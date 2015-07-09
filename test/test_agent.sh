#!/usr/bin/env sh 
curl -H "Content-Type: application/json" --data-binary @$1 http://localhost:8000

