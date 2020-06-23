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

package fi.mpass.shibboleth.attribute.resolver.dc.impl;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.resolver.AttributeDefinition;
import net.shibboleth.idp.attribute.resolver.ResolutionException;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolutionContext;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolverWorkContext;
import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.saml.impl.TestSources;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.protocol.HttpContext;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.simpleframework.http.Request;
import org.simpleframework.http.Response;
import org.simpleframework.http.core.Container;
import org.simpleframework.http.core.ContainerSocketProcessor;
import org.simpleframework.transport.SocketProcessor;
import org.simpleframework.transport.connect.Connection;
import org.simpleframework.transport.connect.SocketConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import fi.mpass.shibboleth.attribute.resolver.data.UserDTO;
import fi.mpass.shibboleth.attribute.resolver.data.UserDTO.RolesDTO;
import fi.mpass.shibboleth.attribute.resolver.dc.impl.RestDataConnector;
import fi.mpass.shibboleth.attribute.resolver.spring.dc.RestDataConnectorParserTest;
import fi.mpass.shibboleth.authn.principal.impl.ShibAttributePrincipal;

/**
 * Unit tests for {@link RestDataConnector}.
 */
public class RestDataConnectorTest {

    /** Class logging. */
    private final Logger log = LoggerFactory.getLogger(RestDataConnectorTest.class);
    
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

    /** The expected resolved OID after successful resolution. */
    private String expectedOid;
    
    /** The expected resolved learnerId after successful resolution. */
    private String expectedLearnerId;
    

    /**
     * Initialize unit tests.
     */
    @BeforeMethod
    public void init() {
        expectedId = "restdc";
        expectedEndpointUrl = "testindEndpointUrl";
        expectedHookAttribute = "testingHookAttribute";
        expectedIdpId = "testingIdpId";
        expectedResultAttribute = "username";
        expectedToken = "testingToken";
        expectedOid = "OID1";
        expectedLearnerId = "1.2.246.562.24.10000000008";
    }
    
    /**
     * Tests constructor.
     */
    @Test public void testConstructor() {
        final HttpClientBuilder builder = new HttpClientBuilder();
        Assert.assertEquals(new RestDataConnector(builder).getHttpClientBuilder(), builder);
        Assert.assertNotNull(new RestDataConnector().getHttpClientBuilder());
    }
    
    /**
     * Tests populateAttribute.
     */
    @Test public void testPopulateAttribute() {
        final RestDataConnector dataConnector = new RestDataConnector();
        dataConnector.setResultAttributePrefix("");        
        final Map<String, IdPAttribute> attributes = new HashMap<>();
        final String name = "mock";
        final String value = "mockValue";
        dataConnector.populateAttribute(attributes, (String)null, (String)null);
        Assert.assertTrue(attributes.isEmpty());
        dataConnector.populateAttribute(attributes, "", (String)null);
        Assert.assertTrue(attributes.isEmpty());
        dataConnector.populateAttribute(attributes, name, (String)null);
        Assert.assertTrue(attributes.isEmpty());
        dataConnector.populateAttribute(attributes, name, "");
        Assert.assertTrue(attributes.isEmpty());
        dataConnector.populateAttribute(attributes, name, value);
        Assert.assertEquals(attributes.size(), 1);
        Assert.assertEquals(attributes.get(name).getValues().size(), 1);
        Assert.assertEquals(attributes.get(name).getValues().get(0).getValue(), value);
    }
    
    /**
     * Tests populateStructuredRole.
     */
    @Test public void testPopulateStructuredRole() {
        final UserDTO user = new UserDTO();
        final RolesDTO role = user.new RolesDTO();
        final Map<String, IdPAttribute> attributes = new HashMap<>();
        final RestDataConnector dataConnector = new RestDataConnector();
        dataConnector.setResultAttributePrefix("");
        dataConnector.populateStructuredRole(attributes, null, null, role);
        final IdPAttribute attribute = attributes.get(RestDataConnector.ATTR_ID_STRUCTURED_ROLES);
        Assert.assertNotNull(attribute);
        Assert.assertEquals(attribute.getValues().size(), 1);
        Assert.assertEquals(attribute.getValues().get(0).getValue(), ";;;");
    }
    
    /**
     * Tests {@link RestDataConnector} with minimum configuration, with empty authnId value.
     */
    @Test(expectedExceptions = ResolutionException.class)
    public void testNoAuthnId() throws Exception {
        expectedHookAttribute = "invalid"; // differs from the configuration
        resolveAttributes("user-0role-0attr.json", "restdc-min.xml");
    }

    /**
     * Tests {@link RestDataConnector} with minimum configuration, with empty idpId value.
     */
    @Test(expectedExceptions = ResolutionException.class)
    public void testNoIdpId() throws Exception {
        expectedIdpId = "invalid"; // differs from the configuration
        resolveAttributes("user-0role-0attr.json", "restdc-min.xml");
    }
    
    /**
     * Tests {@link RestDataConnector} with minimum configuration, without roles for the user.
     * 
     * @throws ComponentInitializationException If component cannot be initialized.
     * @throws ResolutionException If attribute resolution fails.
     */
    @Test
    public void testDefaultNoRoles() throws ComponentInitializationException, ResolutionException, Exception {
        final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("user-0role-0attr.json", 
                "restdc-min.xml");
        Assert.assertEquals(resolvedAttributes.size(), 3);
        Assert.assertEquals(resolvedAttributes.get(expectedResultAttribute).getValues().get(0).getValue(), expectedOid);
    }

    /**
     * Tests {@link RestDataConnector} with minimum configuration, with one teacher role for the user.
     * 
     * @throws ComponentInitializationException If component cannot be initialized.
     * @throws ResolutionException If attribute resolution fails.
     */
    @Test
    public void testResolveAttributes_whenOneTeacherRole_shouldReturnValidUserDTO() 
    		throws ComponentInitializationException, ResolutionException, Exception {
        final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("teacher-1role-1attr.json", 
                "restdc-min.xml");
        Assert.assertEquals(resolvedAttributes.size(), 10);
        Assert.assertEquals(resolvedAttributes.get(expectedResultAttribute).getValues().get(0).getValue(), expectedOid);
        Assert.assertEquals(resolvedAttributes.get("attr_" + RestDataConnector.ATTR_ID_LEARNER_ID), null);
        Assert.assertNull(resolvedAttributes.get(RestDataConnector.ATTR_ID_GROUP_LEVELS));
    }
    
    /**
     * Tests {@link RestDataConnector} with minimum configuration, with one student role for the user.
     * 
     * @throws ComponentInitializationException If component cannot be initialized.
     * @throws ResolutionException If attribute resolution fails.
     */
    @Test
    public void testResolveAttributes_whenOneStudentRole_shouldReturnValidUserDTO() 
    		throws ComponentInitializationException, ResolutionException, Exception {
        final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("student-1role-1attr.json", 
                "restdc-min.xml");
        Assert.assertEquals(resolvedAttributes.size(), 11);
        Assert.assertEquals(resolvedAttributes.get(expectedResultAttribute).getValues().get(0).getValue(), expectedOid);
        final List<IdPAttributeValue<?>> groupLevels 
            = resolvedAttributes.get(RestDataConnector.ATTR_ID_GROUP_LEVELS).getValues();
        Assert.assertTrue(verifyAttributeValueExists(groupLevels, "7"));
        Assert.assertEquals(resolvedAttributes.get("attr_" + RestDataConnector.ATTR_ID_LEARNER_ID).getValues().get(0).getValue(), expectedLearnerId);
    }
    
    /**
     * Tests {@link RestDataConnector} with minimum configuration, with one student role for the user.
     * 
     * @throws ComponentInitializationException If component cannot be initialized.
     * @throws ResolutionException If attribute resolution fails.
     */
    @Test
    public void testResolveAttributes_whenOneStudentRoleWithInvalidGroupLevel_shouldReturnValidUserDTOWithoutGroupLevel() 
    		throws ComponentInitializationException, ResolutionException, Exception {
        final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("student-1role-1attr-invalidGroupLevel.json", 
                "restdc-min.xml");
        Assert.assertEquals(resolvedAttributes.size(), 10);
        Assert.assertEquals(resolvedAttributes.get(expectedResultAttribute).getValues().get(0).getValue(), expectedOid);
        Assert.assertNull(resolvedAttributes.get(RestDataConnector.ATTR_ID_GROUP_LEVELS));
        Assert.assertEquals(resolvedAttributes.get("attr_" + RestDataConnector.ATTR_ID_LEARNER_ID).getValues().get(0).getValue(), expectedLearnerId);
    }

    /**
     * Tests {@link RestDataConnector} with minimum configuration, with two teacher roles for the user.
     * 
     * @throws ComponentInitializationException If component cannot be initialized.
     * @throws ResolutionException If attribute resolution fails.
     */
    @Test
    public void testResolveAttributes_whenTwoTeacherRolesTwoAttributes_shouldReturnValidUserDTO() throws ComponentInitializationException, ResolutionException, Exception {
        final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("teacher-2role-2attr.json", 
                "restdc-min.xml");
        Assert.assertEquals(resolvedAttributes.size(), 11);
        Assert.assertEquals(resolvedAttributes.get(expectedResultAttribute).getValues().get(0).getValue(), expectedOid);
        Assert.assertNull(resolvedAttributes.get(RestDataConnector.ATTR_ID_GROUP_LEVELS));
        Assert.assertNull(resolvedAttributes.get(RestDataConnector.ATTR_ID_LEARNER_ID));
    }
    
    /**
     * Tests {@link RestDataConnector} with minimum configuration, with two student roles for the user.
     * 
     * @throws ComponentInitializationException If component cannot be initialized.
     * @throws ResolutionException If attribute resolution fails.
     */
    @Test
    public void testResolveAttributes_whenTwoStudentRoles_shouldReturnValidUserDTOWithStudentRole() throws ComponentInitializationException, ResolutionException, Exception {
        final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("student-2role-2attr.json", 
                "restdc-min.xml");
        Assert.assertEquals(resolvedAttributes.size(), 12);
        Assert.assertEquals(resolvedAttributes.get(expectedResultAttribute).getValues().get(0).getValue(), expectedOid);
        final List<IdPAttributeValue<?>> groupLevels 
            = resolvedAttributes.get(RestDataConnector.ATTR_ID_GROUP_LEVELS).getValues();
        Assert.assertEquals(groupLevels.size(), 2);
        Assert.assertTrue(verifyAttributeValueExists(groupLevels, "7", "9"));
    }
    
    /**
     * Verifies that all the given values are found from the given list of attributes.
     * 
     * @param output The list of attributes whose contents are verified.
     * @param input The values whose existence is verified from the list of attributes.
     * @return True if all values were found, false otherwise.
     */
    protected boolean verifyAttributeValueExists(final List<IdPAttributeValue<?>> output, String... input) {
        for (final String inputValue : input) {
            boolean found = false;
            for (final IdPAttributeValue<?> value : output) {
                if (inputValue.equals(value.getValue().toString())) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return false;
            }
        }
        return true;
    }

    /**
     * Tests wheter dataconnector settings are valid.
     * @param dataConnector The data connector.
     * @param disregard Whether TLS should be disregarded or not.
     * @param prefix The attribute prefix.
     */
    protected void testSettings(final RestDataConnector dataConnector, final boolean disregard, final String prefix) {
        Assert.assertEquals(dataConnector.getId(), expectedId);
        Assert.assertEquals(dataConnector.getEndpointUrl(), expectedEndpointUrl);
        Assert.assertEquals(dataConnector.getToken(), expectedToken);        
        Assert.assertEquals(dataConnector.isDisregardTLSCertificate(), disregard);
        Assert.assertEquals(dataConnector.getResultAttributePrefix(), prefix);
        Assert.assertNotNull(dataConnector.getHttpClientBuilder());
    }
    
    /**
     * Resolves the attributes with the given settings.
     * @param userJson The User object response simulation from the REST endpoint.
     * @param connectorSettings The settings.
     * @return The map of resolved attributes.
     * @throws Exception
     */
    protected Map<String, IdPAttribute> resolveAttributes(String userJson, String connectorSettings) throws Exception {
        HttpClientBuilder mockBuilder = initializeMockBuilder(userJson);
        final RestDataConnector dataConnector = RestDataConnectorParserTest.initializeDataConnector(connectorSettings);
        final AttributeResolutionContext context = TestSources.createResolutionContext(TestSources.PRINCIPAL_ID, 
                TestSources.IDP_ENTITY_ID, TestSources.SP_ENTITY_ID);
        final AttributeResolverWorkContext workContext =
        context.getSubcontext(AttributeResolverWorkContext.class, false);
        recordWorkContextAttribute(expectedHookAttribute, "hookAttributeValue", workContext);
        recordWorkContextAttribute(expectedIdpId, "idpIdValue", workContext);
        RestDataConnector mockConnector = Mockito.spy(dataConnector);
        Mockito.doReturn(mockBuilder).when(mockConnector).getHttpClientBuilder();
        testSettings(dataConnector, false, "");
        return mockConnector.doResolve(context, workContext);
    }
    
    @Test
    public void testPrincipals() throws Exception {
        Map<String, IdPAttribute> attrs = resolveAttributes("restdc-full.xml", new ShibAttributePrincipal("uid", "uidValue"), new ShibAttributePrincipal("schoolId", "00200"), new ShibAttributePrincipal("role", "Opettaja"));
        Assert.assertEquals(attrs.keySet().size(), 7);
    }
    
    protected Map<String, IdPAttribute> resolveAttributes(String connectorSettings, Principal... principals) throws Exception {
        final RestDataConnector dataConnector = RestDataConnectorParserTest.initializeDataConnector(connectorSettings);
        final AttributeResolutionContext context = TestSources.createResolutionContext(TestSources.PRINCIPAL_ID, 
                TestSources.IDP_ENTITY_ID, TestSources.SP_ENTITY_ID);
        final AttributeResolverWorkContext workContext =
        context.getSubcontext(AttributeResolverWorkContext.class, false);
        recordWorkContextAttribute(expectedHookAttribute, "hookAttributeValue", workContext);
        recordWorkContextAttribute(expectedIdpId, "idpIdValue", workContext);
        final AuthenticationContext authnContext = context.getParent().getSubcontext(AuthenticationContext.class, true);
        final Subject subject = new Subject();
        for (final Principal principal : principals) {
            subject.getPrincipals().add(principal);
        }
        final AuthenticationResult authnResult = new AuthenticationResult("mockFlow", subject);
        authnContext.setAuthenticationResult(authnResult);
        return dataConnector.doResolve(context, workContext);
    }
    
    /**
     * Initializes a mocked {@link HttpClientBuilder}.
     * 
     * @param userJson The user object JSON declaration.
     * @return Mocked {@link HttpClientBuilder}.
     * @throws Exception
     */
    public HttpClientBuilder initializeMockBuilder(String userJson) throws Exception {
        HttpClientBuilder mockBuilder = Mockito.mock(HttpClientBuilder.class);
        CloseableHttpResponse mockResponse = Mockito.mock(CloseableHttpResponse.class);
        StatusLine mockStatusLine = Mockito.mock(StatusLine.class);
        Mockito.doReturn(200).when(mockStatusLine).getStatusCode();
        Mockito.when(mockResponse.getStatusLine()).thenReturn(mockStatusLine);
        HttpClient mockClient = Mockito.mock(HttpClient.class);
        HttpEntity mockEntity = Mockito.mock(HttpEntity.class);
        Mockito.when(mockResponse.getEntity()).thenReturn(mockEntity);
        Mockito.when(mockEntity.getContent()).thenReturn(getUserObjectStream(userJson));
        Mockito.when(mockClient.execute(Matchers.any(HttpUriRequest.class), Matchers.any(HttpContext.class)))
                .thenReturn(mockResponse);
        Mockito.when(mockBuilder.buildClient()).thenReturn(mockClient);
        return mockBuilder;
    }
    
    /**
     * Helper method to point JSON file declaration to correct directory and convert it to {@link InputStream}.
     * @param userJson The JSON filename, without directory prefix.
     * @return The stream corresponding to the file.
     * @throws Exception
     */
    protected InputStream getUserObjectStream(String userJson) throws Exception {
        return new FileInputStream("src/test/resources/fi/mpass/shibboleth/attribute/resolver/data/" + userJson);
    }

    /**
     * Helper method for recording attribute name and value to {@link AttributeResolverWorkContext}.
     * 
     * @param attributeName The attribute name to be recorded.
     * @param attributeValue The attribute value to be recorded.
     * @param workContext The target {@link AttributeResolverWorkContext}.
     * @throws ComponentInitializationException If component cannot be initialized.
     * @throws ResolutionException If attribute recording fails.
     */
    protected void recordWorkContextAttribute(final String attributeName, final String attributeValue,
            final AttributeResolverWorkContext workContext) throws ComponentInitializationException,
            ResolutionException {
        final AttributeDefinition definition = TestSources.populatedStaticAttribute(attributeName, attributeName, 1);
        workContext.recordAttributeDefinitionResolution(definition, populateAttribute(attributeName, attributeValue));
    }

    /**
     * Helper method for populating a String-valued attribute with given parameters.
     * 
     * @param attributeName The attribute name to be populated.
     * @param attributeValue The attribute value.
     * @return The populated {@link IdPAttribute}.
     */
    protected IdPAttribute populateAttribute(final String attributeName, final String attributeValue) {
        IdPAttribute idpAttribute = new IdPAttribute(attributeName);
        final List<IdPAttributeValue<String>> values = new ArrayList<>();
        values.add(new StringAttributeValue(attributeValue));
        idpAttribute.setValues(values);
        return idpAttribute;
    }
    
    @Test
    public void testNullSchoolName() {
        Assert.assertNull(new RestDataConnector().getSchoolName(null, null));
    }

    @Test
    public void testEmptySchoolName() {
        Assert.assertNull(new RestDataConnector().getSchoolName("", null));
    }

    @Test
    public void testNonNumericSchoolName() {
        Assert.assertNull(new RestDataConnector().getSchoolName("mock", null));
    }

    @Test
    public void testLongSchoolName() {
        RestDataConnector c = new RestDataConnector();
        Assert.assertNull(new RestDataConnector().getSchoolName("1234567", null));
    }

    @Test
    public void testSchoolNameException() throws Exception {
        HttpClientBuilder clientBuilder = Mockito.mock(HttpClientBuilder.class);
        HttpClient mockClient = Mockito.mock(HttpClient.class);
        Mockito.when(mockClient.execute((HttpUriRequest)Mockito.any())).thenThrow(new IOException("mock"));
        Mockito.when(clientBuilder.buildClient()).thenReturn(mockClient);
        final RestDataConnector connector = new RestDataConnector(clientBuilder);
        final String name = connector.getSchoolName("123456", "http://localhost/");
        Assert.assertNull(name);
    }

    @Test
    public void testSchoolNameEmptyArray() throws Exception {
        final String name = executeWithServer("[]");
        Assert.assertNull(name);
    }
    
    @Test
    public void testSchoolNameNoMetadata() throws Exception {
        final String name = executeWithServer("[{\"koodiUri\":\"oppilaitosnumero_123456\"," +
                "\"versio\":1,\"koodiArvo\":\"123456\"}]");
        Assert.assertNull(name);
    }
    
    @Test
    public void testSchoolNameEmptyMetadata() throws Exception {
        final String name = executeWithServer("[{\"koodiUri\":\"oppilaitosnumero_123456\",\"metadata\":" + 
                "[],\"versio\":1,\"koodiArvo\":\"123456\"}]");
        Assert.assertNull(name);
    }
    
    @Test
    public void testSchoolNameSuccess() throws Exception {
        final String name = executeWithServer("[{\"koodiUri\":\"oppilaitosnumero_123456\",\"metadata\":" + 
                "[{\"nimi\":\"Mock School Name\",\"lyhytNimi\":\"Mock Short\",\"kieli\":\"FI\"}]," +
                "\"versio\":1,\"koodiArvo\":\"123456\"}]");
        Assert.assertNotNull(name);
        Assert.assertEquals(name, "Mock School Name");
    }
    
    @Test
    public void testSchoolNameMultipleLanguagesInMetadataSuccess() throws Exception {
        final String name = executeWithServer("[{\"koodiUri\":\"oppilaitosnumero_123456\",\"metadata\": [" + 
        		"{\"nimi\":\"Mock skolanamn\",\"lyhytNimi\":\"Mock Kort\",\"kieli\":\"SV\"}," + 
        		"{\"nimi\":\"Mock koulun nimi\",\"lyhytNimi\":\"Mock Lyhyt\",\"kieli\":\"FI\"}," + 
        		"{\"nimi\":\"Mock School Name\",\"lyhytNimi\":\"Mock Short\",\"kieli\":\"EN\"}]," + 
        		"\"versio\":1,\"koodiArvo\":\"123456\"}]");
        Assert.assertNotNull(name);
        Assert.assertEquals(name, "Mock koulun nimi");
    }
    
    @Test
    public void testSchoolNameMultipleLanguagesInMetadataNoFISuccess() throws Exception {
        final String name = executeWithServer("[{\"koodiUri\":\"oppilaitosnumero_123456\",\"metadata\": [" + 
        		"{\"nimi\":\"Mock skolanamn\",\"lyhytNimi\":\"Mock Kort\",\"kieli\":\"SV\"}," + 
        		"{\"nimi\":\"Mock School Name\",\"lyhytNimi\":\"Mock Short\",\"kieli\":\"EN\"}]," + 
        		"\"versio\":1,\"koodiArvo\":\"123456\"}]", "1.2.3.4.5.6");
        Assert.assertNotNull(name);
        Assert.assertEquals(name, "Mock skolanamn");
    }

    protected String executeWithServer(final String responseContent) throws Exception {
    	return executeWithServer(responseContent, null);
    }
    
    protected String executeWithServer(final String responseContent, final String callerId) throws Exception {
        final Container container = new SimpleContainer(responseContent, callerId);
        final SocketProcessor server = new ContainerSocketProcessor(container);
        final Connection connection = new SocketConnection(server);
        final int port = 8997;
        final SocketAddress address = new InetSocketAddress(port);
        connection.connect(address);
        try {
        	RestDataConnector restDataConnector = new RestDataConnector();
        	if (callerId != null) {
        		restDataConnector.setNameApiCallerId(callerId);
        	}
            return restDataConnector.getSchoolName("123456", 
                    "http://localhost:" + port + "/mock");
        } catch (Exception e) {
            log.debug("Catched exception", e);
            return null;
        } finally {
            connection.close();
        }
    }

    /**
     * Simple container implementation.
     */
    class SimpleContainer implements Container {

        final String responseContent;
        final String callerIdHeader;
        /**
         * Constructor.
         */
        public SimpleContainer(final String response) {
        	this(response, null);
        }
        
        public SimpleContainer(final String response, final String callerId) {
        	callerIdHeader = callerId;
            responseContent = response;
        }

        @Override
        /** {@inheritDoc} */
        public void handle(Request request, Response response) {
            log.trace("Server got request for {}", request.getTarget());
            try {
                response.setContentType("application/json");
                Assert.assertEquals(request.getValue(RestDataConnector.HEADER_NAME_CALLER_ID), callerIdHeader);
                
                if (responseContent != null) {
                    IOUtils.copy(new StringReader(responseContent), response.getOutputStream());
                }
                response.setCode(200);
                response.getOutputStream().close();
            } catch (Exception e) {
                log.error("Container-side exception ", e);
            }
        }
    }

}
