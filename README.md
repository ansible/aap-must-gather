# AAP Must Gather

This is a must gather operator for Ansible Automation Platform.

## Purpose

The purpose of this operator is to gather debugging 

## Usage

### Build Image

```
podman build -f Dockerfile --tag quay.io/<username>/aap-must-gather:latest .
podman push quay.io/<username>/aap-must-gather:latest
```

### Run Must Gather

To use this must-gather for Ansible Automation Platform please use the following command:

```
oc adm must-gather --image=quay.io/<username>/aap-must-gather:latest
```

This will create a new directory with the data collected in it, as well as an `event-filter.html` file,
which can be opened in the browser to inspect the event data collected.  

```
$ tree
.
├── collection-scripts
│   └── gather
├── Dockerfile
├── must-gather.local.5507664261615403644
│   ├── event-filter.html
│   ├── quay-io-chadams-aap-must-gather-sha256-25ac61fdb2210cf61b5cb7ce165c42be1512db9004cf8d1b7cd050837b98ae4a
│   │   ├── event-filter.html
│   │   └── timestamp
│   └── timestamp
└── README.md
```
