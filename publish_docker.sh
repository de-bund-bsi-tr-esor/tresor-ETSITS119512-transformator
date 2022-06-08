#!/bin/sh

REGISTRY=public.docker.ecsec.de

# build artifact
mvn clean install -Dquarkus.container-image.registry=$REGISTRY -Dquarkus.container-image.push=true
