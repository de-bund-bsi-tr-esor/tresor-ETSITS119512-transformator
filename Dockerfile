ARG WF_VERSION=latest
FROM jboss/wildfly:${WF_VERSION}

ARG WEBCTX_PATH=tresor-transformator
ADD service/target/tresor-transformator-service.war /opt/jboss/wildfly/standalone/deployments/${WEBCTX_PATH}.war

ENV JAVA_OPTS "-XX:+UseG1GC -Xmx2048m -XX:MaxMetaspaceSize=256m -Djava.net.preferIPv4Stack=true -Djava.awt.headless=true"

# MAX Message size (100MB)
ARG WF_MAX_POST_SIZE=104857600
# augtool fails if file is not group readable
RUN chown jboss.jboss /opt/jboss/wildfly/standalone/configuration/standalone.xml
RUN echo $'\n\
set /augeas/load/Xml/lens Xml.lns \n\
set /augeas/load/Xml/incl /opt/jboss/wildfly/standalone/configuration/standalone.xml \n\
load \n\
defvar server /files/opt/jboss/wildfly/standalone/configuration/standalone.xml/server/profile/subsystem/server[#attribute/name="default-server"] \n\
print $server/http-listener \n\
set $server/http-listener/#attribute/max-post-size "'${WF_MAX_POST_SIZE}$'" \n\
print $server/http-listener \n\
save' \
	| augtool -LA -e
