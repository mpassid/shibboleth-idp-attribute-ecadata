# ECA Data API Connector

[![License](http://img.shields.io/:license-mit-blue.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://travis-ci.org/mpassid/shibboleth-idp-attribute-ecadata.svg?branch=master)](https://travis-ci.org/mpassid/shibboleth-idp-attribute-ecadata)
[![Coverage Status](https://coveralls.io/repos/github/mpassid/shibboleth-idp-attribute-ecadata/badge.svg?branch=master)](https://coveralls.io/github/mpassid/shibboleth-idp-attribute-ecadata?branch=master)

## Overview

This module is a [Data Connector](https://wiki.shibboleth.net/confluence/display/IDP30/Attribute+Resolver)
plugin for [Shibboleth Identity Provider v3](https://wiki.shibboleth.net/confluence/display/IDP30/Home). It
implements the user attribute resolution from ECA Auth Data -module, as defined in [EduCloud Alliance's](https://portal.educloudalliance.org/) [ECA Authentication](https://github.com/educloudalliance/eca-docs/blob/master/auth/index.rst) standard. In short, this module
resolves the user attributes via a specific REST API, using two attributes as a hook to the user object stored
behind the API. In the ECA Auth standard context, those two attributes are [AuthnID](https://github.com/mpassid/shibboleth-idp-attribute-authnid) and IdP identifier.

## Prerequisities and compilation

- Java 7+
- [Apache Maven 3](https://maven.apache.org/)

```
mvn package
```

After successful compilation, the _target_ directory contains _idp-attribute-impl-ecadata-\<version\>.jar_ and
_idp-attribute-impl-ecadata-\<version\>-tests.jar_.

## Deployment

After compilation, the _target/idp-attribute-impl-ecadata-\<version\>.jar_ must be deployed to the IdP Web
application. Depending on the IdP installation, the module deployment may be achieved for instance with the
following sequence:

```
cp target/idp-attribute-impl-ecadata-<version>.jar /opt/shibboleth-idp/edit-webapp/WEB-INF/lib
cd /opt/shibboleth-idp
sh bin/build.sh
```

The final command will rebuild the _war_-package for the IdP application.

## Configuration

### XML-namespace settings

In addition to the existing ones, the _attribute-resolver.xml_ must contain the following XML-namespace
declarations to activate the module:

```
xmlns:ecadata="fi.mpass.shibboleth.attribute.dc.rest"
xsi:schemaLocation="fi.mpass.shibboleth.attribute.dc.rest classpath:/rest-connector.xsd"
```

### Configuration options

The following configuration attributes are available for the _DataConnector_ itself:

- _endpointUrl_: The REST API URL from where the attributes can be fetched.
- _hookAttribute_: The resolved IDP attribute that contains the calculated ECA authnID.
- _idpId_: The resolved IDP attribute that contains the stored IDP identifier for authnID.
- _resultAttributePrefix_: The IDP attribute id prefix that will be used for the resulting attributes.
- _token_: The authorization token registered to the ECA DATA API.
- _disregardTLSCertificate_: Set to 'true' to skip endpoint certificate validation.

### Example configuration

An example snippet of configuration in _attribute-resolver.xml_, which uses _authnid_ and _idpId_ attributes
as hooks and records the attributes with prefix _eca_. The _username_ returned by the REST API will be encoded
to a SAML 2 attribute called _urn:TODO:namespace:username_:

```
<resolver:AttributeDefinition id="ecausername" xsi:type="ad:Simple">
    <resolver:Dependency ref="ecaDataApi" />
    <resolver:AttributeEncoder 
      xsi:type="enc:SAML2String" 
      name="urn:TODO:namespace:username" 
      friendlyName="username" 
      encodeType="false" />
</resolver:AttributeDefinition>

<resolver:DataConnector 
  id="ecaDataApi" 
  xsi:type="ecadata:RestDataConnector" 
  endpointUrl="https://eca-data.example.org/api/1/user" 
  hookAttribute="authnid" 
  idpId="idpId" 
  resultAttributePrefix="eca" 
  token="secrettoken12345" 
  disregardTLSCertificate="false">
    <resolver:Dependency ref="authnid" />
    <resolver:Dependency ref="idpId" />
</resolver:DataConnector>
```
