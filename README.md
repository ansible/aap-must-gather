# AAP Must Gather

A comprehensive must-gather tool for debugging Ansible Automation Platform (AAP) deployments on OpenShift.

## Features

- **Complete AAP Data Collection**: Gathers logs, configurations, and resource status from all AAP components
- **InitContainer Logs**: Captures startup logs from initContainers for troubleshooting deployment issues
- **Database Migration Status**: Collects Django migration status from Controller, Gateway, and EDA components
- **Resource Analysis**: Comprehensive collection of PVCs, deployments, services, and other Kubernetes resources
- **Error Analysis**: Automated error detection with intelligent filtering and HTML summary reports
- **Interactive Interface**: Professional HTML navigation interface for easy data exploration

## Quick Start

### Build and Push Image

```bash
# Build the image
podman build -f Dockerfile --tag quay.io/<username>/aap-must-gather:latest .

# Push to registry
podman push quay.io/<username>/aap-must-gather:latest
```

### Run Must Gather

```bash
# Collect AAP debugging data
oc adm must-gather --image=quay.io/<username>/aap-must-gather:latest
```

### View Results

Open the generated `index.html` file in your browser to navigate the collected data:

```bash
# Find the output directory
ls -la must-gather.local.*

# Open the interactive interface
open must-gather.local.*/index.html
```

## Local Development and Testing

### Test Script Functionality

```bash
# Test individual components without cluster connection
bash test-enhanced-status.sh
bash test-real-data.sh

# View generated test outputs
open test-*-output.html
```

### Test with Local Cluster

```bash
# Run the gather script directly (requires oc access)
BASE_COLLECTION_PATH="./test-output" bash collection-scripts/gather

# View results
open test-output/index.html
```

### Validate Script Syntax

```bash
# Check for syntax errors
bash -n collection-scripts/gather

# Run enhanced tests
bash test-enhanced-gather.sh
```

## Output Structure

```
must-gather.local.*/
├── index.html                    # Interactive navigation interface
├── reports/
│   ├── summary-report.html       # Error analysis and version info
│   └── error-summary.log         # Detailed error findings
├── logs/                         # InitContainer and pod logs
├── commands/                     # ShowMigrations and other command outputs
├── pvc-status.log               # Storage information
├── deployments.log              # Deployment status
├── services.log                 # Service configurations
└── [standard must-gather files] # OpenShift cluster data
```

## Troubleshooting

- **Permission Issues**: Ensure your user has cluster-admin or appropriate RBAC permissions
- **Image Pull Errors**: Verify the image is accessible from your cluster
- **Missing Data**: Check that AAP is deployed and pods are running in expected namespaces

For detailed enhancement information, see [ENHANCEMENT_SUMMARY.md](ENHANCEMENT_SUMMARY.md).
