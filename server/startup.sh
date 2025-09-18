#!/bin/sh
set -eu

OUTPUT_PATH="$TEMPORAL_CONFIG_PATH/$TEMPORAL_CONFIG_FILENAME.yaml"

export POD_IP=$(hostname -i)

# Render the template
dockerize -template $TEMPORAL_CONFIG_TEMPLATE_PATH:$OUTPUT_PATH

echo "Rendered Temporal config to: $OUTPUT_PATH"
echo "----- Config Start -----"
cat "$OUTPUT_PATH"
echo "----- Config End -----"

/app/temporal-auth-server