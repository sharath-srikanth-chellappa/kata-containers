# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# Example:
#
# git clone https://github.com/microsoft/kata-containers.git
# cd kata-containers/src/tools/genpolicy
#
# mkdir -p /tmp/genpolicy
# sudo DOCKER_BUILDKIT=1 docker build --no-cache --output /tmp/genpolicy --build-arg GENPOLICY_BRANCH="msft-main" .
#
# RUST_LOG=info /tmp/genpolicy/genpolicy -p /tmp/genpolicy/rules.rego -j /tmp/genpolicy/genpolicy-settings.json -y ../../agent/samples/policy/yaml/pod/pod-one-container.yaml

FROM mcr.microsoft.com/cbl-mariner/base/core:2.0 AS genpolicy-build-stage

RUN tdnf install -y \
    build-essential \
    ca-certificates \
    cmake \
    git \
    openssl-static \
    protobuf-compiler \
    rust 

# Get genpolicy source code.
WORKDIR /src
ARG GENPOLICY_BRANCH="msft-main"
RUN git clone https://github.com/microsoft/kata-containers.git -b "${GENPOLICY_BRANCH}"

# Build from source code.
WORKDIR /src/kata-containers/src/tools/genpolicy
RUN OPENSSL_STATIC=1 \
    OPENSSL_LIB_DIR=/usr/lib \
    OPENSSL_INCLUDE_DIR=/usr/include/openssl \
    LIBC=gnu \
    make build

# Copy the files needed for executing genpolicy into the --output directory of "DOCKER_BUILDKIT=1 docker build".
FROM scratch
COPY --from=genpolicy-build-stage /src/kata-containers/src/tools/genpolicy/target/x86_64-unknown-linux-gnu/release/genpolicy .
COPY --from=genpolicy-build-stage /src/kata-containers/src/tools/genpolicy/genpolicy-settings.json .
COPY --from=genpolicy-build-stage /src/kata-containers/src/tools/genpolicy/rules.rego .
