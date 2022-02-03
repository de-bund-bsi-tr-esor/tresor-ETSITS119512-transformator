# ETSI TS119512 TR-ESOR Transformator

The ETSI TS119512 TR-ESOR Transformator (or short TR-ESOR Transformator) consists of a webservice according to ETSI TS 119 512, which is capable of transforming incoming ETSI TS 119 512 (V1.1.2) messages into TR-ESOR S4 (V1.3.0) messages which are sent to an attached TR-ESOR system.
It allows a compliant TR-ESOR system to be used with a webservice client according to ETSI TS 119 512 and the BSI profile (`http://www.bsi.bund.de/tr-esor/V1.2.2/profile/preservation-api/V1.1.2`) without the need to change the TR-ESOR system.

## Prerequisites

In order to build the web application, at least the following software is needed:

* Apache Maven ≥ 3.6.0
* Java JDK ≥ 11

Alternatively the Software can be run in a docker container or with docker-compose as described in Section [Docker](#docker).

# Build/Run Instructions

The source code is structured as two maven modules, one for the schema transformation into Java model classes (wsdl) and one quarkus-based webservice.

In order to build the software, the following statements must be executed:
```
$ mvn clean install
```
## Quarkus

It is possible to start a standalone service by
```
$ mvn clean compile quarkus:dev -Dquarkus.http.port=<PORT>
```
which will start the service listening on port <PORT>


## Docker-compose

The TR-ESOR Transformator can be run with docker-compose. For that, two compose configs are provided.

First the TR-ESOR Transformator must be configured correctly.
Within `docker-config` there is a simple config as a starting point.
At least the URL of the mock service must be changed. (see [Configuration](#Configuration))
Note that the docker container can reach the network of the host, but it may have different knowledge of hostnames. (localhost will not work as docker resolves this to itself for example)
That means if the S4 endpoint seems not to be reachable by the TR-ESOR Transformator, it might help to use the hosts IP address instead of a resolvable name as the endpoint URL.

The main `docker-compose.yml` defines that the latest version of the image will be pulled from the docker registry.
The config directory will be copied into a volume, so that the webapp can read it.

The system can then be started with:

```
$ docker-compose up
```

In case it is desirable to build the docker container yourself, the `docker-compose.dev.yml` file can be added to the executing command.
When doing so, first build the docker image by
```
$ mvn install -Pdocker
```

The docker service can then be started with:

```
$ docker-compose  -f docker-compose.yml -f docker-compose.dev.yml up --build
```


# Configuration

Before TR-ESOR Transformator can be started, it needs to be configured by adjusting the configuration and by providing additional parameters such as a keystore if needed.
Where the properties have to be set depends on how the service is started.

The quarkus based services contains a
`application.properties`
file which is bundled with the service.
If quarkus is used as described earlier, the configuration has to be adjusted there.

If docker-compose is used, the configuration can be adjusted within the `docker-config` folder and the file `application.properties`.
The values set there will override those being defined in the bundled `application.properties`.

Alternatively one can adjust the `docker-compose.yml` and adjust the path of `quarkus.config.location` to load alternative properties-files
while using docker.


The following configuration options can or have to be set and adjusted within the properties-file:


## PreservationEndpoint

* `quarkus.cxf.endpoint.PreservationService.wsdl`

  Path to the wsdl of the public Preservation endpoint.

* `tresor.trans.endpoint.schema-validation-enabled`
 
  Allows to configure schema validation. The following values are possible:
    - IN: Validation active for incoming requests
    - OUT: Validation active for outgoing requests
    - BOTH: Both of the above
    - NONE: None of the above
    - TRUE: Same as BOTH
    - FALSE: Same as NONE

  Defaults to NONE. 

* `tresor.trans.endpoint.mtom-enabled`
  
  Enables MTOM for the PreservationService endpoint. 

  Default is disabled.


## S4 client 

* `quarkus.cxf.client.s4Client.client-endpoint-url`

  The URL of the S4 service which is masqueraded as PreservationService by the tresor-transformator.

* `quarkus.cxf.client.s4Client.soap-binding`
  
  This allows to configure the soap-binding for messages between transformator and S4 service.
  It allows to switch the usage of MTOM by choosing one of: 

    - http://www.w3.org/2003/05/soap/bindings/HTTP/?mtom=true 
    - http://www.w3.org/2003/05/soap/bindings/HTTP/

  Default is:  http://www.w3.org/2003/05/soap/bindings/HTTP/


### S4 client authentication

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

* `tresor.trans.client.saml-ecp-config.token-element`

  Qualified name of the token element in the form {NAMESPACE}LOCALPART

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
