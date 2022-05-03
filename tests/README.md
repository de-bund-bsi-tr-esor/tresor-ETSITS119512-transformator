# ETSI TS119512 TR-ESOR Transformator: Tests

Following documentation describes the process of testing of the ETSI TS119512 TR-ESOR Transformator (or short TR-ESOR Transformator).

## Prerequisites

In order to use the predefined test, at leats the following software packages are required:

* SoapUI - downloadable at [https://www.soapui.org/](https://www.soapui.org/ "https://www.soapui.org/") (also as an open source - community version)
* Optional - in case you are using a SopaUI package without bundeled Java Runtime Environment (JRE) , you will need to download a corresponding JRE and install it (please consult for more information the documentation of SoapUI)

## Configuration

The configuration of the test environemnt consist of two steps:

* generation of the required test data - in order to do that, please change to subdirectory *data/lt-data* and execute the script *gen-rdata.sh*. After a while (it generates some couple of random data and assemble it into aour test data packages) it should produce following files, which will be used in order to execute throughput tests (mtom with big payload):
    - tst_5M.bin
    - tst_10M.bin
    - tst_25M.bin
    - tst_50M.bin
    - tst_100M.bin
    - tst_250M.bin
    - tst_500M.bin

* import the both SoapUI projects into your running SoapUI instance:
    * **S4-soapui-project.xml** - consists the mock service *S4-Mock-Service* which checks the incoming requests and simulate a responses of a TR-ESOR-System.
    * **S512-soapui-project.xml** - consist three test suits, corresponding to functional *S512-TestSuite*, throughput *S512-TestSuite-LT* and last tests *S512-TestSuite-Load*.

* configure the access urls:
    * TR-ESOR Transformator - per default ist set to: *http://bsi-transformator:8080/tresor-transformator-service/ws/PreservationService*, you can change it in the SoapUI and assign the new URL to all test cases (please consult the SoapUI documentation, how to do that)
    * S4-Mock - you can specify which network interface should the mock service bind to (it could be localhost or the real IP adress of the host SoapUI isr running on). Per default, following settings will be used:
        * Host: bsi-transformator
        * Port: 8888
        * Path: /mockS4  

## Tests

The tests are divied into three separated categories:

### Functional tests

Test suite: **S512-TestSuite**

In order to proof the functional correctness of the TR-ESOR Transformator (according to the current specification), a set of functional tests have to be executed. Before you execute the tests, plase be sure the TR-ESOR Transformator and the S4-mock-service are both up and running.

### Throughput tests

Test suite: **S512-TestSuite-LT**

This test suite proofs the ability of the TR-ESOR Transformator to deal with payload of an increased size. The tests use the payload data generated while the configuration step.

Be sure you have configured your application server properly, in order to be able handle requests containing huge data. The test suite sends (among others) requests of more than 500 MB in size. Furthermore, it is important to increase the max stack size of SOAP-UI's JVM.    

### Load tests

Test suite: **S512-TestSuite-Load**

By using this tests, you can check the behaviour of the TR-ESOR Transformator while sending multiple requests in parallel.
