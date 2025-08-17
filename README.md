# Access Control Explorer

[![Test](https://github.com/CameronXie/access-control-explorer/actions/workflows/test.yaml/badge.svg)](https://github.com/CameronXie/access-control-explorer/actions/workflows/test.yaml)

## Purpose

Access Control Explorer is designed to facilitate the exploration and implementation of modern access control
architectures. The project provides reusable libraries and practical examples to evaluate different access control
mechanisms in terms of their effectiveness, performance, and adaptability to real-world scenarios.

The primary objective is to offer developers and security practitioners a comprehensive toolkit for understanding and
implementing sophisticated access control patterns, with emphasis on attribute-based access control (ABAC) and its
practical applications.

## Components

### ABAC Library

The [`abac/`](abac/) directory contains a general-purpose ABAC library following XACML-style architecture:

- **Decision Maker (Policy Decision Point)**: Policy decision maker with configurable policy resolvers
- **Policy Provider (Policy Retrieval Point)**: Policy provider with file-based storage support
- **Enforcer (Policy Enforcement Point)**: Enforcement interfaces and implementations
- **Request Orchestrator (Context Handler)**: Request orchestrator for enriching access requests with contextual attributes
- **Info Provider (Policy Information Point)**: Information provider for enriching requests with additional contextual data
- **Policy Evaluator**: Policy evaluation engine with OPA/Rego implementation for policy execution
- **Extensions**: Support for obligations, advices, and custom information providers

The library provides clean interfaces that can be extended with custom implementations for different deployment
scenarios and policy requirements.

### Examples

#### REST API with ABAC Enforcement

The [`examples/abac/`](examples/abac/) directory demonstrates a complete implementation of ABAC enforcement in a REST
API context:

- **E-commerce Use Case**: Order management system with role-based permissions implemented through ABAC
- **HTTP Middleware**: Enforcer (Policy Enforcement Point) as HTTP middleware
- **JWT Authentication**: Token-based authentication with RS256 signing and automatic user context enrichment
- **Policy Implementation**: Rego policies implementing RBAC patterns within ABAC framework
- **Obligations and Advices**: Practical examples of audit logging and caching hints

For detailed setup and usage instructions, see the [ABAC Example README](examples/abac/README.md).

## Development Setup

This project uses Docker and Docker Compose for local development environment setup.

### Prerequisites

- Docker and Docker Compose
- Make

### Local Environment

Create and start the development environment:

```shell
make up
```

This command:

- Generates RSA key pairs for JWT signing/verification if not present
- Creates the necessary `.env` file from `.env.example`
- Starts all required services via Docker Compose

Stop the development environment:

```shell
make down
```

### Testing

Run the complete test suite:

```shell 
make test
```

This includes:

- GitHub Actions linting
- Go code linting and formatting
- Go unit tests with race detection and coverage analysis

For Go-specific tests only:

```shell
make test-go
```

Test all examples in the project:

```shell
make test-examples
```

This command iterates through all example directories and runs their individual test suites, ensuring that all practical
implementations work correctly with the core ABAC library.

Test artifacts are generated in `_dist/tests/` including coverage reports.

### Code Quality

Lint Go code:

```shell
make lint-go
```

Lint GitHub Actions workflows:

```shell
make lint-actions
```

## Contributing

1. Ensure Docker and Make are installed
2. Run `make up` to set up the development environment
3. Make your changes
4. Run `make test` to verify all tests pass
5. Submit your pull request
