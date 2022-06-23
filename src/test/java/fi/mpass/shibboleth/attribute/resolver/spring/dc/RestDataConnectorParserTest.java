/*
 * The MIT License
 * Copyright (c) 2015 CSC - IT Center for Science, http://www.csc.fi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package fi.mpass.shibboleth.attribute.resolver.spring.dc;


import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import fi.mpass.shibboleth.attribute.resolver.dc.impl.RestDataConnector;
import net.shibboleth.idp.attribute.resolver.spring.BaseAttributeDefinitionParserTest;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Unit tests for {@link RestDataConnectorParser}.
 */
public class RestDataConnectorParserTest extends BaseAttributeDefinitionParserTest {
    
    /** The expected data connector id. */
    private String expectedId;
    
    /** The expected endpointUrl value. */
    private String expectedEndpointUrl;
    
    /** The expected hookAttribute value. */
    private String expectedHookAttribute;
    
    /** The expected idpId value. */
    private String expectedIdpId;
    
    /** The expected resultAttribute value. */
    private String expectedResultAttribute;
    
    /** The expected token value. */
    private String expectedToken;
    
    /** The expected name api base URL value. */
    private String expectedNameApiBaseUrl;
    
    /** The expected caller-id value for name API. */
    private String expectedNameApiCallerId;
    
    /**
     * Initialize unit tests.
     */
    @BeforeTest public void init() {
        expectedId = "restdc";
        expectedEndpointUrl = "testindEndpointUrl";
        expectedHookAttribute = "testingHookAttribute";
        expectedIdpId = "testingIdpId";
        expectedResultAttribute = "testingPrefix";
        expectedToken = "testingToken";
        expectedNameApiBaseUrl = "http://localhost:8997/mock_";
        expectedNameApiCallerId = "testingCallerId";
    }
    
    /**
     * Tests parsing of the {@link RestDataConnector} from XML configuration with only required configuration
     * parameters set.
     * 
     * @throws ComponentInitializationException If data connector initialization fails.
     */
    @Test public void testMinimum() throws ComponentInitializationException {
        final RestDataConnector dataConnector = initializeDataConnector("restdc-min.xml");
        Assert.assertEquals(dataConnector.getId(), expectedId);
        Assert.assertNull(dataConnector.getFailoverDataConnectorId());
        Assert.assertEquals(dataConnector.getEndpointUrl(), expectedEndpointUrl);
        Assert.assertEquals(dataConnector.getHookAttribute(), expectedHookAttribute);
        Assert.assertEquals(dataConnector.getIdpId(), expectedIdpId);
        Assert.assertEquals(dataConnector.getResultAttributePrefix(), "");
        Assert.assertFalse(dataConnector.isDisregardTLSCertificate());
        Assert.assertEquals(dataConnector.getToken(), expectedToken);
        Assert.assertEquals(dataConnector.getNameApiBaseUrl(), expectedNameApiBaseUrl);
        Assert.assertNull(dataConnector.getNameApiCallerId());
    }

    /**
     * Tests parsing of the {@link RestDataConnector} from XML configuration with optional parameters set.
     *
     * @throws ComponentInitializationException If data connector initialization fails.
     */
    @Test public void testFull() throws ComponentInitializationException {
        final RestDataConnector dataConnector = initializeDataConnector("restdc-full.xml");
        Assert.assertEquals(dataConnector.getId(), expectedId);
        Assert.assertNull(dataConnector.getFailoverDataConnectorId());
        Assert.assertEquals(dataConnector.getEndpointUrl(), expectedEndpointUrl);
        Assert.assertEquals(dataConnector.getHookAttribute(), expectedHookAttribute);
        Assert.assertEquals(dataConnector.getIdpId(), expectedIdpId);
        Assert.assertEquals(dataConnector.getResultAttributePrefix(), expectedResultAttribute);
        Assert.assertTrue(dataConnector.isDisregardTLSCertificate());
        Assert.assertEquals(dataConnector.getToken(), expectedToken);
        Assert.assertEquals(dataConnector.getNameApiBaseUrl(), expectedNameApiBaseUrl);
        Assert.assertEquals(dataConnector.getNameApiCallerId(), expectedNameApiCallerId);
        Assert.assertNotNull(dataConnector.getSchoolRoleMappings());
        Assert.assertEquals(dataConnector.getSchoolRoleMappings().get("teacher"), "Opettaja");
        Assert.assertFalse(dataConnector.getAllowedSchoolRoles().isEmpty());
        Assert.assertEquals(dataConnector.getAllowedSchoolRoles().size(), 6);
        Assert.assertEquals(dataConnector.getStudentRoles().size(), 1);
        Assert.assertTrue(dataConnector.getStudentRoles().contains("Oppilas"));
    }

    /**
     * Constructs and initializes an instance of {@link RestDataConnector} as configured in
     * the given file.
     * 
     * @param configFile The configuration file for the data connector.
     * @return Returns the configured data connector.
     */
    public static RestDataConnector initializeDataConnector(final String configFile) {
        RestDataConnectorParserTest instance = new RestDataConnectorParserTest();
        return instance.getDataConnector(configFile, RestDataConnector.class);
    }
}
