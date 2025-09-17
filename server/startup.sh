#!/bin/sh
set -eu

OUTPUT_PATH="$TEMPORAL_CONFIG_PATH/$TEMPORAL_CONFIG_FILENAME.yaml"

# Render the template
gomplate -f "$TEMPORAL_CONFIG_TEMPLATE_PATH" -o "$OUTPUT_PATH"

echo "Rendered Temporal config to: $OUTPUT_PATH"

/app/temporal-auth-server