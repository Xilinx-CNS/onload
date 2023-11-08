# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc.

ARG SOURCE_IMAGE=onload-source-subdir
ARG BUILDER_UBI_BASE=redhat/ubi8-minimal:8.8
ARG USER_BASE=redhat/ubi8-micro:8.8
ARG URL=https://github.com/Xilinx-CNS/onload
ARG PRODUCT=Onload
ARG VENDOR=Advanced Micro Devices, Inc.


# Onload source image when context is top level or tarball contains subdir
FROM scratch as onload-source-root
ARG PRODUCT
ARG VERSION
ARG ONLOAD_LOCATION=${PRODUCT}-${VERSION}.tgz
# hadolint ignore=DL3020
ADD $ONLOAD_LOCATION /


# Onload source image when context is subdir
FROM scratch as onload-source-subdir
ARG PRODUCT
ARG BRAND=$PRODUCT
ARG VERSION
ARG CREATED
ARG REVISION
ARG TITLE="$BRAND Source Code"
ARG DESCRIPTION="$TITLE, version $VERSION"
ARG SOURCE
ARG VENDOR
ARG URL
LABEL \
  name="$TITLE" \
  summary="$TITLE" \
  description="$DESCRIPTION" \
  maintainer="$VENDOR" \
  vendor="$VENDOR" \
  version="$VERSION" \
  release="$VERSION" \
  com.amd.onload.product="$PRODUCT" \
  com.amd.onload.brand="$BRAND" \
  org.opencontainers.image.title="$TITLE" \
  org.opencontainers.image.description="$DESCRIPTION" \
  org.opencontainers.image.version="$VERSION" \
  org.opencontainers.image.created="$CREATED" \
  org.opencontainers.image.revision="$REVISION" \
  org.opencontainers.image.source="$SOURCE" \
  org.opencontainers.image.url="$URL" \
  org.opencontainers.image.licenses="GPL-2.0 OR BSD-2-Clause"
USER 1001
COPY --from=onload-source-root ${PRODUCT}-${VERSION} /
COPY --from=onload-source-root \
  ${PRODUCT}-${VERSION}/LICENSE \
  ${PRODUCT}-${VERSION}/LICENSES-ALL \
  /licenses/


# Workaround to make 'source' a variable
# https://github.com/moby/moby/issues/34482
FROM $SOURCE_IMAGE as source


# Build stage image
FROM $BUILDER_UBI_BASE as user-builder
ARG ONLOAD_BUILD_PARAMS
ARG SOURCE_ROOT=/

# Install requirements for building Onload userland
# hadolint ignore=DL3040
RUN microdnf install -y \
  bash \
  binutils \
  gawk \
  gcc \
  gcc-c++ \
  gettext \
  glibc-common \
  gzip \
  libpcap-devel \
  make \
  perl-Test-Harness \
  sed \
  tar \
  which

# libcap headers are needed to build onload. The installation of the
# headers on RHEL is normally handled by installing the rpm package libcap-devel.
# However, that package is not available in the standard ubi8
# package repositories, so to get around this issue the package is
# downloaded, built and installed manually.
# START libcap
WORKDIR /root
RUN microdnf -y --enablerepo="ubi-*-baseos-source" download --source libcap
RUN mkdir libcap && \
    rpm -i libcap-*.src.rpm && \
    tar xzf rpmbuild/SOURCES/libcap-*.tar.gz --strip-components=1 -C libcap && \
    make -C libcap/libcap install
# END libcap

# Build userland components
COPY --from=source $SOURCE_ROOT /opt/onload-source
COPY --from=source $SOURCE_ROOT/LICENSES-ALL $SOURCE_ROOT/LICENSE /licenses/
WORKDIR /opt/onload-source/
RUN scripts/onload_build --user $ONLOAD_BUILD_PARAMS

# Install userland within image
ENV i_prefix=/opt/onload
RUN mkdir /opt/onload && \
    scripts/onload_install --nobuild --userfiles


# Onload userland image
FROM $USER_BASE
ARG PRODUCT
ARG BRAND=$PRODUCT
ARG VERSION
ARG CREATED
ARG REVISION
ARG TITLE="$BRAND Userland"
ARG DESCRIPTION="$TITLE, version $VERSION"
ARG SOURCE
ARG SOURCE_IMAGE_DIGEST
ARG VENDOR
ARG URL
LABEL \
  name="$TITLE" \
  summary="$TITLE" \
  description="$DESCRIPTION" \
  maintainer="$VENDOR" \
  vendor="$VENDOR" \
  version="$VERSION" \
  release="$VERSION" \
  vcs-ref="$REVISION" \
  build-date="$CREATED" \
  url="$URL" \
  com.amd.onload.product="$PRODUCT" \
  com.amd.onload.brand="$BRAND" \
  com.amd.onload.source.image.digest="$SOURCE_IMAGE_DIGEST" \
  org.opencontainers.image.title="$TITLE" \
  org.opencontainers.image.description="$DESCRIPTION" \
  org.opencontainers.image.version="$VERSION" \
  org.opencontainers.image.created="$CREATED" \
  org.opencontainers.image.revision="$REVISION" \
  org.opencontainers.image.source="$SOURCE" \
  org.opencontainers.image.url="$URL" \
  org.opencontainers.image.licenses="GPL-2.0 OR BSD-2-Clause" \
  org.opencontainers.image.base.name="$USER_BASE"
COPY --from=user-builder /opt/onload /opt/onload
COPY --from=user-builder /licenses /
WORKDIR /opt/onload
USER 1001
ENV ONLOAD_PRELOAD=/opt/onload/usr/lib64/libonload.so
ENTRYPOINT [ "/opt/onload/usr/bin/onload" ]
CMD [ "--version" ]
