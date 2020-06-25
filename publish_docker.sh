#!/bin/sh

NAME=public.docker.ecsec.de/tresor/transformator
VERSION=$(xmlstarlet sel -B -N pom="http://maven.apache.org/POM/4.0.0" -t -c "/pom:project/pom:version/text()" pom.xml)

if [ -z $VERSION ]; then
	echo "Version could not be determined."
	exit 1
elif [ `echo $VERSION | grep -e '^.\+-SNAPSHOT$'` ]; then
	echo "This build is a SNAPSHOT version, skip publishing."
	exit 2
fi


# build artifact
mvn clean install

# build and publish named image
docker build --tag $NAME:${VERSION} .
docker push $NAME:${VERSION}

# publish latest image
docker tag $NAME:${VERSION} $NAME:latest
docker push $NAME:latest
