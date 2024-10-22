FROM golang:1.23-bookworm

RUN set -eux \
    && apt-get update && apt-get install -y --no-install-recommends \
      apt-transport-https \
      ca-certificates \
      curl \
      git \
      gnupg \
      jq \
      less \
      lsb-release \
      make \
      shellcheck \
      tree \
      vim \
      zip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ARG ACTIONLINT_VERSION=1.7.3
ARG GOLANGCILINT_VERSION=1.61.0

WORKDIR /tmp/build
RUN \
    # install golangcli-lint
    curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | \
        sh -s -- -b $(go env GOPATH)/bin v${GOLANGCILINT_VERSION} \
    # install actionlint
    && wget -q -O actionlint.tar.gz https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz \
    && tar -xzf actionlint.tar.gz \
    && mv actionlint /usr/local/bin \
    && rm -rf /tmp/build
