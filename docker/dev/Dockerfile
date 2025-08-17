FROM golang:1.24-bookworm

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

ARG ACTIONLINT_VERSION=1.7.7
ARG GOLANGCILINT_VERSION=2.1.6
ARG GOLANG_MIGRATE_VERSION=4.18.3

WORKDIR /tmp/build
RUN set -eux \
    # install golangcli-lint
    && curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | \
        sh -s -- -b $(go env GOPATH)/bin v${GOLANGCILINT_VERSION} \
    # install actionlint
    && wget -q -O actionlint.tar.gz https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz \
    && tar -xzf actionlint.tar.gz \
    && mv actionlint /usr/local/bin \
    # install golang-migrate
    && curl -L https://github.com/golang-migrate/migrate/releases/download/v${GOLANG_MIGRATE_VERSION}/migrate.linux-amd64.tar.gz | tar xvz \
    && mv migrate /usr/local/bin \
    && rm -rf /tmp/build
