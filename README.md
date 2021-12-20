# ETSI TS119512 TR-ESOR Transformator

The ETSI TS119512 TR-ESOR Transformator (or short TR-ESOR Transformator) consists of a webservice according to ETSI TS 119 512, which is capable of transforming incoming ETSI TS 119 512 (V1.1.2) messages into TR-ESOR S4 (V1.2.2) messages which are sent to an attached TR-ESOR system.
It allows a compliant TR-ESOR system to be used with a webservice client according to ETSI TS 119 512 and the BSI profile (`http://www.bsi.bund.de/tr-esor/V1.2.2/profile/preservation-api/V1.1.2`) without the need to change the TR-ESOR system.
The [specification document](BSI-TR-03125-512-S4-TRANSFORMATOR-V1_2_1-V1_2_2.pdf) contains the technical information about the profile, that is necessary to interface with the TR-ESOR Transformator.

## Prerequisites

In order to build the web application, at least the following software is needed:

* Apache Maven ≥ 3.6.0
* Java JDK ≥ 11

In order to run the application, at least the following software is needed:

* WildFly <https://wildfly.org>  ≥ 18
* Java JDK ≥ 11

Alternatively the Software can be run in a docker container or with docker-compose as described in Section [Docker](#docker).


# Build Instructions

The source code is structured as two maven modules, one for the schema transformation into Java model classes (wsdl) and one web archive which can be deployed to an application server (service).

The service module emits a jar file containing the code and a war file bundling it to a deployable service.
With this separation the TR-ESOR Transformator can be easily added to another web application.


In order to build the software, the following statements must be executed:
```
$ mvn clean install
```

The resulting artefact can be found in the directory `service/target/`.

## Docker

The source contains a Dockerfile with which a docker image can be created.
In order for the docker container to build properly, the source must be compiled as described in the previous section.



# Installation

The TR-ESOR Transformator ca be run in a JavaEE 7 compliant application server using CXF as the included JAX-WS Framework.

After a successful deployment the webservice endpoint is provided at the following path relative to the root of the webapp.

```
/ws/PreservationService?wsdl
```

In case of the docker-compose deployment the complete URL of the webservice is as follows.

```
http://localhost:8080/tresor-transformator/ws/PreservationService?wsdl
```


The following subsections describe two possibilities how the service can be deployed.
Note that the docker deployment is recommended as it simplifies the deployment process.


## Standalone Application Server

WildFly (<https://wildfly.org>) is the recommended application server to run an instance of the TR-ESOR Transformator.
Java in at least a version ≥ 11 is required in order to run the TR-ESOR Transformator.

Detailed instructions on how to operate and deploy a webapp to the application server can be found in the WildFly documentation at <https://docs.wildfly.org/>.

Instructions how to configuration of the TR-ESOR Transformator can be found in section [Configuration](#configuration).


## docker-compose

The TR-ESOR Transformator can be run with docker-compose. For that two compose configs are provided.

First the TR-ESOR Transformator must be configured correctly.
The docker-config folder contains a simple config as a starting point.
In this config file, at least the URL of the mock service must be changed.
Note that the docker container can reach the network of the host, but it may have different knowledge of hostnames.
That means if the S4 endpoint seems not to be reachable by the TR-ESOR Transformator, it might help to use the hosts IP address instead of a resolvable name as the endpoint URL.

The main `docker-compose.yml` defines that the latest version of the image will be pulled from the docker registry.
The config directory will be copied into a volume, so that the webapp can read it.

The system can then be started with:

```
$ docker-compose up
```

In case it is desirable to build the docker container yourself, the `docker-compose.dev.yml` file can be added to the executing command.
When doing so make sure that the maven build succeeded prior to starting docker-compose.

The system can then be started with:

```
$ docker-compose  -f docker-compose.yml -f docker-compose.dev.yml up --build
```


# Configuration

Before the TR-ESOR Transformator can be started, it needs to be configured by adjusting the configuration file `application.properties` and by providing additional parameters such as a keystore if needed.


The following configuration options are required in order to run the service.

* `quarkus.cxf.client."s4-client".client-endpoint-url`

  URL of the S4 endpoint.

* `tresor.trans.service.profile-filepath`

  Path to an XML file containing the profile returned in the `RetrieveInfoResponse` message of the 512 interface.
  The builtin profile located in the source tree (`service/src/main/resources/config/profile.xml`) can be used as starting point for modifications.
  The bundled file is also used if no path is configured.


For authentication of the S4 webservice client module, credentials have to be provided which fit the S4 service used.

If the S4 service requires TLS client certificates the following parameters have to be configured:

* `tresor.trans.client.tls-config.truststore-filepath`

  Path to a JKS truststore used to validate the S4 endpoint's TLS certificate.

* `tresor.trans.client.tls-config.keystore-filepath`

  Path to a JKS or PKCS12 keystore containing the client certificate needed to authenticate the webservice client at the S4 endpoint.

* `tresor.trans.client.tls-config.keystore-secret`

  Password of the keystore and the key entry.



If the S4 service requires SAML Ecp tokens the following parameters have to be configured:

* `tresor.trans.client.saml-ecp-config.authn-url`

  URL for the SAML-ECP AuthnRequest.

* `tresor.trans.client.saml-ecp-config.ecp-url`

  URL for the ECP authentication endpoint.

* `tresor.trans.client.saml-ecp-config.acs-url`

  URL for the SAML Assertion Consumer Service endpoint.

* `tresor.trans.client.saml-ecp-config.token-header-name`

  URL for the SAML Assertion Consumer Service endpoint.

* `tresor.trans.client.saml-ecp-config.user`

  Username used during the authentication process.

* `tresor.trans.client.saml-ecp-config.pass`

  Password used during the authentication process.

* `tresor.trans.client.saml-ecp-config.token-validity`

  Duration value such as 12h.
  Access tokens are renewed automatically after this period is elapsed.


# Test

A SoapUI Testsuite and instructions on how to use it can be found in the [tests](tests) directory.


# License

This software is underlying the rules of the following license: Apache License Version 2.0, January 2004.

The software was created by ecsec GmbH on behalf of the Federal Office for Information Security.


## Contact

Federal Office for Information Security (BSI)<br>
Godesberger Allee 185-189<br>
53175 Bonn, Germany<br>
phone: +49 228 99 9582-0<br>
fax: +49 228 99 9582-5400<br>
e-mail: bsi@bsi.bund.de

and

ecsec GmbH<br>
Sudentenstraße 16<br>
96247 Michelau, Germany<br>
Sudetenstraße 16<br>
phone: +49 9571 948 1020<br>
e-mail: info@ecsec.de
