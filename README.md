# AAP Must Gather

A comprehensive must-gather tool for debugging Ansible Automation Platform (AAP) deployments on OpenShift.

## Features

- **Complete AAP Data Collection**: Gathers logs, configurations, and resource status from all AAP components
- **InitContainer Logs**: Captures startup logs from initContainers for troubleshooting deployment issues
- **Database Migration Status**: Collects Django migration status from Controller, Gateway, and EDA components
- **Resource Analysis**: Comprehensive collection of PVCs, deployments, services, and other Kubernetes resources
- **Error Analysis**: Automated error detection with intelligent filtering and HTML summary reports
- **Interactive Interface**: Professional HTML navigation interface for easy data exploration

## Usage

### Production Use

```bash
# Collect AAP debugging data from your cluster
oc adm must-gather --image=quay.io/<username>/aap-must-gather:latest
```

### Testing/Development

```bash
# Test the gather script directly (requires oc access to cluster)
BASE_COLLECTION_PATH="./test-output" bash collection-scripts/gather
```

### View Results

Open the generated `index.html` file in your browser to navigate the collected data:

```bash
# For production must-gather output
ls -la must-gather.local.*
open must-gather.local.*/index.html

# For testing output
open test-output/index.html
```

## Output Structure

```
must-gather.local.*/
├── summary/                      # Summary info, events, node status
├── operators/                    # CSV, subscriptions, install plans
├── cluster/                      # Cluster version, dmesg logs
├── namespaces/<ns>/              # Per-namespace logs, configs, commands
├── logs/                         # Container logs (current and previous)
├── commands/                     # Management command outputs (sanitized)
├── configs/                      # Config files (redis.conf, nginx.conf, etc.)
├── resources/                    # Deployments, services, PVCs, routes
├── must-gather/                  # OMC-compatible standard must-gather tree
├── reports/                      # Summary report (with --render-webpage)
└── index.html                    # HTML viewer (with --render-webpage)
```

## OMC Compatibility

This must-gather tool is fully compatible with the [OpenShift Must-Gather Client (OMC)](https://github.com/gmeghnag/omc). You can use OMC to query the collected data using familiar `oc` commands:

```bash
# Point OMC to the must-gather output
omc use must-gather.local.*/

# Query AAP resources
omc get automationcontroller -A
omc get pods -n <aap-namespace> -o wide
```

## Troubleshooting

- **Permission Issues**: Ensure your user has cluster-admin or appropriate RBAC permissions
- **Image Pull Errors**: Verify the image is accessible from your cluster
- **Missing Data**: Check that AAP is deployed and pods are running in expected namespaces
