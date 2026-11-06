# syntax=docker/dockerfile:1
# Runs ci/fastapi-deploy.sh on a Depot builder (ci/depot-deploy.sh): the build
# is the deploy, nothing is pushed. Secrets come in as an env file, never layers.
FROM python:3.13-slim
WORKDIR /repo
COPY . .
ARG DEPLOY_ID
RUN --mount=type=secret,id=deploy_env,target=/run/secrets/deploy_env \
    echo "deploy $DEPLOY_ID" && set -a && . /run/secrets/deploy_env && set +a && bash ci/fastapi-deploy.sh
