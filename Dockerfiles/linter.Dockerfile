# This version number must be kept in sync with CI workflow lint one.
ARG IMAGE=golangci/golangci-lint:v2.15.0@sha256:fbfcfd12a6f8d7f1b97b3362ca80fc2a244d46863148c73cb88e7793af96c481
FROM ${IMAGE}

# The timeout specified below is used by 'make lint'. Please keep in sync with
# the timeout specified in .golangci.yml used by the CI.
ENTRYPOINT ["golangci-lint", "run", "--fix", "--timeout=10m0s"]
