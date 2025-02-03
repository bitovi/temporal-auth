load('ext://dotenv', 'dotenv')

allow_k8s_contexts('docker-desktop')

# Force everything to deploy to the `temporal` namespace
k8s_namespace('temporal')

# Load environment variables
dotenv()

# Create Kubernetes secret from environment variables
k8s_yaml(blob("""
apiVersion: v1
kind: Secret
metadata:
  name: temporal-auth-secrets
  namespace: temporal
type: Opaque
stringData:
  issuer_url: "{}"
  client_id: "{}"
  client_secret: "{}"
""".format(
    os.getenv('TEMPORAL_AUTH_ISSUER_URL', ''),
    os.getenv('TEMPORAL_AUTH_CLIENT_ID', ''),
    os.getenv('TEMPORAL_AUTH_CLIENT_SECRET', '')
)))

# Build custom Temporal server with auth
docker_build(
    'temporal-auth-server',
    './server',  # Use server directory as context
    dockerfile='server/Dockerfile'
)

# Generate Helm manifests and apply them in Tilt
local_resource(
    'helm-temporal',
    cmd='''
    set -e
    echo "🔍 Ensuring namespace 'temporal' exists..."
    kubectl get namespace temporal || kubectl create namespace temporal

    echo "📝 Generating Helm template for Temporal..."
    helm template temporal temporal/temporal -f ./k8s/dev/values-dev.yaml --namespace temporal > ./k8s/dev/temporal-generated.yaml
    ''',
    deps=['./k8s/dev/values-dev.yaml']
)

k8s_yaml([
    "k8s/dev/postgres.yaml"  # Define a standalone PostgreSQL deployment
])

k8s_resource('postgres', port_forwards=['5432:5432'])

# Apply the generated manifests
k8s_yaml('./k8s/dev/temporal-generated.yaml')

# Ensure Tilt tracks Helm-installed Temporal pods
k8s_resource('temporal-frontend', port_forwards=['7233:7233'])
k8s_resource('temporal-web', port_forwards=['8080:8080'])
k8s_resource('temporal-worker')
k8s_resource('temporal-matching')
k8s_resource('temporal-history')