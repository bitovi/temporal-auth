#!/bin/sh
set -eu

OUTPUT_PATH="$TEMPORAL_CONFIG_PATH/$TEMPORAL_CONFIG_FILENAME.yaml"

POD_IP=$(hostname -i)

# Render the template
gomplate -f "$TEMPORAL_CONFIG_TEMPLATE_PATH" -o "$OUTPUT_PATH"

echo "Rendered Temporal config to: $OUTPUT_PATH"
echo "----- Config Start -----"
cat "$OUTPUT_PATH"
echo "----- Config End -----"

/app/temporal-auth-server