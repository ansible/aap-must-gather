# Copyright (c) 2021 Red Hat, Inc.
# Copyright Contributors to the Ansible project

FROM quay.io/openshift/origin-cli:4.20 as builder

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

RUN microdnf update -y \
    && microdnf install -y tar rsync findutils gzip iproute util-linux \
    && microdnf clean all

# Copy oc binary
COPY --from=builder /usr/bin/oc /usr/bin/oc

# copy all collection scripts to /usr/bin
COPY collection-scripts/* /usr/bin/

ENTRYPOINT /usr/bin/gather
