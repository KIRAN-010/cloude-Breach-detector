#!/usr/bin/env bash
set -euo pipefail
: "${TRAIL_ARN:?Set TRAIL_ARN}"
: "${START_TIME:?Set START_TIME in ISO8601}"
: "${END_TIME:?Set END_TIME in ISO8601}"
mkdir -p output
aws cloudtrail validate-logs --trail-arn "$TRAIL_ARN" --start-time "$START_TIME" --end-time "$END_TIME" --verbose > output/integrity-validation.txt 2>&1
cat output/integrity-validation.txt
# Inspect and record invalid files AND missing digest periods; retain output with the case.
