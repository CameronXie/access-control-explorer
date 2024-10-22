# Access Control Explorer

[![Test](https://github.com/CameronXie/access-control-explorer/actions/workflows/test.yaml/badge.svg)](https://github.com/CameronXie/access-control-explorer/actions/workflows/test.yaml)

AccessControlExplorer is a project designed to facilitate the testing and exploration of various access control
architectures and models. The objective is to perform a thorough evaluation of different access control mechanisms in
terms of their effectiveness, performance, and adaptability.

## Features

| Access Control Model             | Description              | Build Command     |
|----------------------------------|--------------------------|-------------------|
| Role-Based Access Control (RBAC) | implemented using Casbin | `make api-casbin` |
| Role-Based Access Control (RBAC) | implemented using OPA    | `make api-opa`    |

## API Endpoints

The API endpoints for the access control models are registered in the [`internal/api/api.go`](internal/api/rest/api.go)
file.

## Getting Started

1. Clone the repository and change into the directory.
2. This project uses Docker for the local development environment. To start the Docker container and generate the RSA
   key pair for JWTs, run `make up`. This command also sets the necessary environment variables, such as
   `PRIVATE_KEY_BASE64` and `PUBLIC_KEY_BASE64`, for the RSA keys.
3. Inside the Docker container, use the build commands from the [features](#features) table to compile the specific API.
   For example: `make api-opa`.
4. Inside the Docker container, run the compiled API located in the `_dist/build` directory. For example:
   `_dist/build/api-opa`.
5. Access the API via [http://localhost:8080](http://localhost:8080).

## Test

To run the tests, simply execute the following command `make test`. This command will perform GitHub Actions linting, Go
code linting, and Go unit tests to ensure the code quality and functionality.
