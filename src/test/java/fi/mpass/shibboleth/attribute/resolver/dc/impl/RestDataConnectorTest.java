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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;

import org.apache.commons.io.IOUtils;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.message.StatusLine;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.mockito.ArgumentMatchers;
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

import fi.csc.shibboleth.authn.principal.impl.ShibAttributePrincipal;
import fi.mpass.shibboleth.attribute.resolver.data.School;
import fi.mpass.shibboleth.attribute.resolver.data.UserDTO;
import fi.mpass.shibboleth.attribute.resolver.data.UserDTO.RolesDTO;
import fi.mpass.shibboleth.attribute.resolver.spring.dc.RestDataConnectorParserTest;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.resolver.AttributeDefinition;
import net.shibboleth.idp.attribute.resolver.ResolutionException;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolutionContext;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolverWorkContext;
import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.saml.impl.testing.TestSources;
import net.shibboleth.shared.collection.Pair;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.httpclient.HttpClientBuilder;

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

	/** The expected school ids values. */
	private String expectedSchoolId;
	private String expectedSchoolId2;

	/** The expected school oids values. */
	private String expectedSchoolOid;
	private String expectedSchoolOid2;

	/** The expected school names values. */
	private String expectedSchoolName;
	private String expectedSchoolName2;

	/** The expected office oid value. */
	private String expectedOfficeOid;
	private String expectedOfficeOid2;

	/** The expected office name value. */
	private String expectedOfficeName;
	private String expectedOfficeName2;

	/** The expected school info values. */
	private String expectedSchoolInfo;

	/** The expected parent oids values. */
	private String expectedParentOid;
	private String expectedParentOid2;

	/** The expected parent names values. */
	private String expectedParentName;
	private String expectedParentName2;

	/** The expected parent info values. */
	private String expectedParentInfo;
	
	private String expectedOrganizationType;

	/**
	 * Initialize unit tests.
	 */
	@BeforeMethod
	public void init() {
		expectedEndpointUrl = "testindEndpointUrl";
		expectedHookAttribute = "testingHookAttribute";
		expectedId = "restdc";
		expectedIdpId = "testingIdpId";
		expectedLearnerId = "1.2.246.562.24.10000000008";
		expectedOid = "OID1";
		expectedParentOid = "1.2.246.562.10.10000000001";
		expectedParentOid2 = "1.2.246.562.10.10000000002";
		expectedParentName = "Mock Education Provider Name";
		expectedParentName2 = "Mock Education Provider Name 2";
		expectedOfficeOid = "1.2.246.562.10.30000000001";
		expectedOfficeName = "Mock Office Name";
		expectedOfficeOid2 = "1.2.246.562.10.30000000002";
		expectedOfficeName2 = "Mock Office Name2";
		expectedParentInfo = expectedParentOid + ";" + expectedParentName;
		expectedResultAttribute = "username";
		expectedSchoolId = "12345";
		expectedSchoolOid = "1.2.246.562.10.12345";
		expectedSchoolId2 = "23456";
		expectedSchoolOid2 = "1.2.246.562.10.23456";
		expectedSchoolName = "Mock School Name";
		expectedSchoolName2 = "Mock School Name 2";
		expectedSchoolInfo = expectedSchoolId + ";" + expectedSchoolName;
		expectedToken = "testingToken";
		expectedOrganizationType = "organisaatiotyyppi_02";
	}

	/**
	 * Tests constructor.
	 */
	@Test
	public void testConstructor() {
		final HttpClientBuilder builder = new HttpClientBuilder();
		Assert.assertEquals(new RestDataConnector(builder).getHttpClientBuilder(), builder);
		Assert.assertNotNull(new RestDataConnector().getHttpClientBuilder());
	}

	/**
	 * Tests populateAttribute.
	 */
	@Test
	public void testPopulateAttribute() {
		final RestDataConnector dataConnector = new RestDataConnector();
		dataConnector.setResultAttributePrefix("");
		final Map<String, IdPAttribute> attributes = new HashMap<>();
		final String name = "mock";
		final String value = "mockValue";
		dataConnector.populateAttribute(attributes, (String) null, (String) null);
		Assert.assertTrue(attributes.isEmpty());
		dataConnector.populateAttribute(attributes, "", (String) null);
		Assert.assertTrue(attributes.isEmpty());
		dataConnector.populateAttribute(attributes, name, (String) null);
		Assert.assertTrue(attributes.isEmpty());
		dataConnector.populateAttribute(attributes, name, "");
		Assert.assertTrue(attributes.isEmpty());
		dataConnector.populateAttribute(attributes, name, value);
		Assert.assertEquals(attributes.size(), 1);
		Assert.assertEquals(attributes.get(name).getValues().size(), 1);
		Assert.assertEquals(attributes.get(name).getValues().get(0).getNativeValue(), value);
		dataConnector.populateAttribute(attributes, name, " " + value);
		Assert.assertEquals(attributes.get(name).getValues().get(0).getDisplayValue(), value);
		dataConnector.populateAttribute(attributes, name, value + " ");
		Assert.assertEquals(attributes.get(name).getValues().get(0).getDisplayValue(), value);
	}

	/**
	 * Tests populateStructuredRole with school id and school name.
	 */
	@Test
	public void testPopulateStructuredRole() {
		final UserDTO user = new UserDTO();
		final RolesDTO role = user.new RolesDTO();
		final Map<String, IdPAttribute> attributes = new HashMap<>();
		final RestDataConnector dataConnector = new RestDataConnector();
		dataConnector.setResultAttributePrefix("");
		dataConnector.populateStructuredRole(attributes, null, null, role);
		final IdPAttribute attribute = attributes.get(RestDataConnector.ATTR_ID_STRUCTURED_ROLES);
		Assert.assertNotNull(attribute);
		Assert.assertEquals(attribute.getValues().size(), 1);
		Assert.assertEquals(attribute.getValues().get(0).getNativeValue(), ";;;");
	}

	/**
	 * Tests populateStructuredRole with school object.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testPopulateStructuredRole_whenSchoolObjectAsParam_shouldReturnRoleWithParentOid() {
		final UserDTO user = new UserDTO();
		final RolesDTO role = user.new RolesDTO();
		final Map<String, IdPAttribute> attributes = new HashMap<>();
		final RestDataConnector dataConnector = new RestDataConnector();
		dataConnector.setResultAttributePrefix("");

		final String expected = expectedParentOid + ";" + expectedSchoolId + ";;;;"+expectedSchoolOid+";";

		School school = new School(expectedSchoolId, expectedSchoolName, expectedSchoolOid, expectedParentOid, expectedParentName);
		dataConnector.populateStructuredRole(attributes, school, role);
		final IdPAttribute attribute = attributes.get(RestDataConnector.ATTR_ID_STRUCTURED_ROLES_WITH_PARENT_OID);
		
		Assert.assertNotNull(attribute);
		Assert.assertEquals(attribute.getValues().size(), 1);
		Assert.assertEquals(attribute.getValues().get(0).getNativeValue(), expected);
	}

	@Test
	public void testPopulateStructuredRole_whenSchoolWithOfficeObjectAsParam_shouldReturnRoleWithParentOid() {
		final UserDTO user = new UserDTO();
		final RolesDTO role = user.new RolesDTO();
		final Map<String, IdPAttribute> attributes = new HashMap<>();
		final RestDataConnector dataConnector = new RestDataConnector();
		dataConnector.setResultAttributePrefix("");

		final String expected = expectedParentOid + ";" + expectedSchoolId + ";;;;"+expectedSchoolOid+";"+expectedOfficeOid;

		School school = new School(expectedSchoolId, expectedSchoolName, expectedSchoolOid, expectedOfficeOid,expectedOfficeName , expectedParentOid, expectedParentName, expectedOrganizationType);
		dataConnector.populateStructuredRole(attributes, school, role);
		final IdPAttribute attribute = attributes.get(RestDataConnector.ATTR_ID_STRUCTURED_ROLES_WITH_PARENT_OID);
		
		Assert.assertNotNull(attribute);
		Assert.assertEquals(attribute.getValues().size(), 1);
		Assert.assertEquals(attribute.getValues().get(0).getNativeValue(), expected);

	}

	/**
	 * 
	 * @throws Exception
	 */
	@Test
	public void testPopulateRolesDTOs_whenOneRoleAttriburesEach_shouldReturnOneRolesDTO() {
		final RestDataConnector dataConnector = new RestDataConnector();
		dataConnector.setResultAttributePrefix("");

		RolesDTO expectedRole = new UserDTO().new RolesDTO();
		expectedRole.setGroup("7C");
		expectedRole.setGroupLevel(7);
		expectedRole.setMunicipality("Helsinki");
		expectedRole.setRole("Oppilas");
		expectedRole.setSchool("12345");

		RolesDTO[] actualRoles = dataConnector.populateRolesDTOs("12345", "7C", "Oppilas", null, "7", "Helsinki");
		Assert.assertEquals(actualRoles.length, 1);
		Assert.assertEquals(actualRoles[0].toString(), expectedRole.toString());
	}
	
	/**
	 * 
	 * @throws Exception
	 */
	@Test
	public void testPopulateRolesDTOs_whenRoleWithLearningMaterialsCharge_shouldReturnRolesDTO() {
		final RestDataConnector dataConnector = new RestDataConnector();
		dataConnector.setResultAttributePrefix("");
		Set<String> studentRoles = new HashSet<String>();
		studentRoles.add("Oppilas");
		dataConnector.setStudentRoles(studentRoles);

		RolesDTO expectedRole = new UserDTO().new RolesDTO();
		expectedRole.setGroup("7C");
		expectedRole.setGroupLevel(7);
		expectedRole.setMunicipality("Helsinki");
		expectedRole.setRole("Oppilas");
		expectedRole.setSchool("12345");
		expectedRole.setLearningMaterialsCharge(0);

		RolesDTO[] actualRoles = dataConnector.populateRolesDTOs("12345", "7C", "Oppilas", "0", "7", "Helsinki");
		Assert.assertEquals(actualRoles.length, 1);
		Assert.assertEquals(actualRoles[0].toString(), expectedRole.toString());
	}
	
	/**
	 * 
	 * @throws Exception
	 */
	@Test
	public void testPopulateRolesDTOs_whenThreeRoleAttriburesEach_shouldReturnThreeRolesDTO() {
		final RestDataConnector dataConnector = new RestDataConnector();
		dataConnector.setResultAttributePrefix("");

		RolesDTO expectedRole1 = new UserDTO().new RolesDTO();
		expectedRole1.setGroup("7C");
		expectedRole1.setGroupLevel(7);
		expectedRole1.setMunicipality("Helsinki");
		expectedRole1.setRole("Oppilas");
		expectedRole1.setSchool("12345");

		RolesDTO expectedRole2 = new UserDTO().new RolesDTO();
		expectedRole2.setGroup("5A");
		expectedRole2.setGroupLevel(null);
		expectedRole2.setMunicipality("Helsinki");
		expectedRole2.setRole("Oppilas");
		expectedRole2.setSchool("23456");

		RolesDTO expectedRole3 = new UserDTO().new RolesDTO();
		expectedRole3.setGroup("8B");
		expectedRole3.setGroupLevel(null);
		expectedRole3.setMunicipality("Helsinki");
		expectedRole3.setRole("Oppilas");
		expectedRole3.setSchool("34567");

		RolesDTO[] actualRoles = dataConnector.populateRolesDTOs("12345;23456;34567", "7C;5A;8B",
				"Oppilas;Oppilas;Oppilas", null,  "7", "Helsinki");
		Assert.assertEquals(actualRoles.length, 3);
		Assert.assertEquals(actualRoles[0].toString(), expectedRole1.toString());
		Assert.assertEquals(actualRoles[1].toString(), expectedRole2.toString());
		Assert.assertEquals(actualRoles[2].toString(), expectedRole3.toString());
	}

	/**
	 * 
	 * @throws Exception
	 */
	@Test
	public void testPopulateRolesDTOs_whenThreeSchoolCodesAndGroupsAndOneSchoolRole_shouldReturnThreeRolesDTO() {
		final RestDataConnector dataConnector = new RestDataConnector();
		dataConnector.setResultAttributePrefix("");

		RolesDTO expectedRole1 = new UserDTO().new RolesDTO();
		expectedRole1.setGroup("7C");
		expectedRole1.setGroupLevel(7);
		expectedRole1.setMunicipality("Helsinki");
		expectedRole1.setRole("Oppilas");
		expectedRole1.setSchool("12345");

		RolesDTO expectedRole2 = new UserDTO().new RolesDTO();
		expectedRole2.setGroup("5A");
		expectedRole2.setGroupLevel(null);
		expectedRole2.setMunicipality("Helsinki");
		expectedRole2.setRole("Oppilas");
		expectedRole2.setSchool("23456");

		RolesDTO expectedRole3 = new UserDTO().new RolesDTO();
		expectedRole3.setGroup("8B");
		expectedRole3.setGroupLevel(null);
		expectedRole3.setMunicipality("Helsinki");
		expectedRole3.setRole("Oppilas");
		expectedRole3.setSchool("34567");

		RolesDTO[] actualRoles = dataConnector.populateRolesDTOs("12345;23456;34567", "7C;5A;8B", "Oppilas", null, "7",
				"Helsinki");
		Assert.assertEquals(actualRoles.length, 3);
		Assert.assertEquals(actualRoles[0].toString(), expectedRole1.toString());
		Assert.assertEquals(actualRoles[1].toString(), expectedRole2.toString());
		Assert.assertEquals(actualRoles[2].toString(), expectedRole3.toString());
	}
	
	@Test
	public void testPopulateRolesDTOs_whenMultipleRolesWithLearningMaterialsCharges_shouldReturnThreeRolesDTO() {
		final RestDataConnector dataConnector = new RestDataConnector();
		dataConnector.setResultAttributePrefix("");
		
		Set<String> studentRoles = new HashSet<String>();
		studentRoles.add("Oppilas");
		dataConnector.setStudentRoles(studentRoles);
		

		RolesDTO expectedRole1 = new UserDTO().new RolesDTO();
		expectedRole1.setGroup("7C");
		expectedRole1.setGroupLevel(7);
		expectedRole1.setMunicipality("Helsinki");
		expectedRole1.setRole("Oppilas");
		expectedRole1.setSchool("12345");
		expectedRole1.setLearningMaterialsCharge(1);

		RolesDTO expectedRole2 = new UserDTO().new RolesDTO();
		expectedRole2.setGroup("5A");
		expectedRole2.setGroupLevel(null);
		expectedRole2.setMunicipality("Helsinki");
		expectedRole2.setRole("Oppilas");
		expectedRole2.setSchool("23456");
		expectedRole2.setLearningMaterialsCharge(0);

		RolesDTO expectedRole3 = new UserDTO().new RolesDTO();
		expectedRole3.setGroup("8B");
		expectedRole3.setGroupLevel(null);
		expectedRole3.setMunicipality("Helsinki");
		expectedRole3.setRole("Oppilas");
		expectedRole3.setSchool("34567");
		expectedRole3.setLearningMaterialsCharge(1);

		RolesDTO[] actualRoles = dataConnector.populateRolesDTOs("12345;23456;34567", "7C;5A;8B", "Oppilas", "1;0;1", "7",
				"Helsinki");
		Assert.assertEquals(actualRoles.length, 3);
		Assert.assertEquals(actualRoles[0].toString(), expectedRole1.toString());
		Assert.assertEquals(actualRoles[1].toString(), expectedRole2.toString());
		Assert.assertEquals(actualRoles[2].toString(), expectedRole3.toString());
	}

	/**
	 * 
	 * @throws Exception
	 */
	@Test
	public void testPopulateRolesDTOs_whenThreeSchoolCodesAndOneGroupAndOneSchoolRole_shouldReturnThreeRolesDTO() {
		final RestDataConnector dataConnector = new RestDataConnector();
		dataConnector.setResultAttributePrefix("");

		RolesDTO expectedRole1 = new UserDTO().new RolesDTO();
		expectedRole1.setGroup("7C");
		expectedRole1.setMunicipality("Helsinki");
		expectedRole1.setRole("Opettaja");
		expectedRole1.setSchool("12345");

		RolesDTO expectedRole2 = new UserDTO().new RolesDTO();
		expectedRole2.setMunicipality("Helsinki");
		expectedRole2.setRole("Opettaja");
		expectedRole2.setSchool("23456");

		RolesDTO expectedRole3 = new UserDTO().new RolesDTO();
		expectedRole3.setMunicipality("Helsinki");
		expectedRole3.setRole("Opettaja");
		expectedRole3.setSchool("34567");

		RolesDTO expectedRole4 = new UserDTO().new RolesDTO();
		expectedRole4.setMunicipality("Helsinki");
		expectedRole4.setRole("Opettaja");
		expectedRole4.setSchool("45678");

		RolesDTO[] actualRoles = dataConnector.populateRolesDTOs("12345;23456;34567", "7C;;", "Opettaja", null,  null,
				"Helsinki");
		Assert.assertEquals(actualRoles.length, 3);
		Assert.assertEquals(actualRoles[0].toString(), expectedRole1.toString());
		Assert.assertEquals(actualRoles[1].toString(), expectedRole2.toString());
		Assert.assertEquals(actualRoles[2].toString(), expectedRole3.toString());

		actualRoles = dataConnector.populateRolesDTOs("23456;12345;34567", ";7C;", "Opettaja", null,  null, "Helsinki");
		Assert.assertEquals(actualRoles.length, 3);
		Assert.assertEquals(actualRoles[0].toString(), expectedRole2.toString());
		Assert.assertEquals(actualRoles[1].toString(), expectedRole1.toString());
		Assert.assertEquals(actualRoles[2].toString(), expectedRole3.toString());

		actualRoles = dataConnector.populateRolesDTOs("23456;34567;12345", ";;7C", "Opettaja", null,  null, "Helsinki");
		Assert.assertEquals(actualRoles.length, 3);
		Assert.assertEquals(actualRoles[0].toString(), expectedRole2.toString());
		Assert.assertEquals(actualRoles[1].toString(), expectedRole3.toString());
		Assert.assertEquals(actualRoles[2].toString(), expectedRole1.toString());

		actualRoles = dataConnector.populateRolesDTOs("23456;34567;45678", ";;", "Opettaja", null,  null, "Helsinki");
		Assert.assertEquals(actualRoles.length, 3);
		Assert.assertEquals(actualRoles[0].toString(), expectedRole2.toString());
		Assert.assertEquals(actualRoles[1].toString(), expectedRole3.toString());
		Assert.assertEquals(actualRoles[2].toString(), expectedRole4.toString());
	}

	/**
	 * 
	 * @throws Exception
	 */
	@Test
	public void testPopulateRolesDTOs_whenRoleAttributesNotValid_shouldReturnNull() {
		final RestDataConnector dataConnector = new RestDataConnector();
		dataConnector.setResultAttributePrefix("");

		RolesDTO expectedRole1 = new UserDTO().new RolesDTO();
		expectedRole1.setGroup("7C");
		expectedRole1.setMunicipality("Helsinki");
		expectedRole1.setRole("Opettaja");
		expectedRole1.setSchool("12345");

		RolesDTO expectedRole2 = new UserDTO().new RolesDTO();
		expectedRole2.setMunicipality("Helsinki");
		expectedRole2.setRole("Opettaja");
		expectedRole2.setSchool("23456");

		RolesDTO expectedRole3 = new UserDTO().new RolesDTO();
		expectedRole3.setMunicipality("Helsinki");
		expectedRole3.setRole("Opettaja");
		expectedRole3.setSchool("34567");

		// RolesDTO[] actualRoles = dataConnector.populateRolesDTOs(null, "7C;;",
		// "Opettaja", null, "Helsinki" );
		// Assert.assertNull(actualRoles);

		RolesDTO[] actualRoles = dataConnector.populateRolesDTOs("12345;23456;34567", "7C;;", "Opettaja;Sijaisopettaja",
				null,  null, "Helsinki");
		Assert.assertNull(actualRoles);

		actualRoles = dataConnector.populateRolesDTOs("12345;23456;34567", "7C;", "Opettaja", null, null, "Helsinki");
		Assert.assertNull(actualRoles);

		actualRoles = dataConnector.populateRolesDTOs("12345;23456;34567", ";7C", "Opettaja", null, null, "Helsinki");
		Assert.assertNull(actualRoles);

		actualRoles = dataConnector.populateRolesDTOs("12345;23456;34567", ";7C",
				"Opettaja;Sijaisopettaja;Sijaisopettaja", null, null, "Helsinki");
		Assert.assertNull(actualRoles);

		actualRoles = dataConnector.populateRolesDTOs("12345;23456;34567", ";", "Opettaja", null, null, "Helsinki");
		Assert.assertNull(actualRoles);
	}

	/**
	 * 
	 * @throws Exception
	 */
	@Test
	public void testPopulateRolesDTOs_whenThreeSchoolCodesAndOneSchoolRole_shouldReturnThreeRolesDTO() {
		final RestDataConnector dataConnector = new RestDataConnector();
		dataConnector.setResultAttributePrefix("");

		RolesDTO expectedRole1 = new UserDTO().new RolesDTO();
		expectedRole1.setMunicipality("Helsinki");
		expectedRole1.setRole("Opettaja");
		expectedRole1.setSchool("12345");

		RolesDTO expectedRole2 = new UserDTO().new RolesDTO();
		expectedRole2.setMunicipality("Helsinki");
		expectedRole2.setRole("Opettaja");
		expectedRole2.setSchool("23456");

		RolesDTO expectedRole3 = new UserDTO().new RolesDTO();
		expectedRole3.setMunicipality("Helsinki");
		expectedRole3.setRole("Opettaja");
		expectedRole3.setSchool("34567");

		RolesDTO[] actualRoles = dataConnector.populateRolesDTOs("12345;23456;34567", null, "Opettaja", null, null,
				"Helsinki");
		Assert.assertEquals(actualRoles.length, 3);
		Assert.assertEquals(actualRoles[0].toString(), expectedRole1.toString());
		Assert.assertEquals(actualRoles[1].toString(), expectedRole2.toString());
		Assert.assertEquals(actualRoles[2].toString(), expectedRole3.toString());
	}

	/**
	 * Tests {@link RestDataConnector} with minimum configuration, with empty
	 * authnId value.
	 */
	@Test(expectedExceptions = ResolutionException.class)
	public void testNoAuthnId() throws Exception {
		expectedHookAttribute = "invalid"; // differs from the configuration
		resolveAttributes("user-0role-0attr.json", "restdc-min.xml");
	}

	/**
	 * Tests {@link RestDataConnector} with minimum configuration, with empty idpId
	 * value.
	 */
	@Test(expectedExceptions = ResolutionException.class)
	public void testNoIdpId() throws Exception {
		expectedIdpId = "invalid"; // differs from the configuration
		resolveAttributes("user-0role-0attr.json", "restdc-min.xml");
	}

	/**
	 * Tests {@link RestDataConnector} with minimum configuration, without roles for
	 * the user.
	 * 
	 * @throws ComponentInitializationException If component cannot be initialized.
	 * @throws ResolutionException              If attribute resolution fails.
	 */
	@Test
	public void testDefaultNoRoles() throws ComponentInitializationException, ResolutionException, Exception {
		final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("user-0role-0attr.json",
				"restdc-min.xml");
		Assert.assertEquals(resolvedAttributes.size(), 3);
		Assert.assertEquals(resolvedAttributes.get(expectedResultAttribute).getValues().get(0).getNativeValue(),
				expectedOid);
	}

	/**
	 * Tests {@link RestDataConnector} with minimum configuration, with one teacher
	 * role for the user.
	 * 
	 * @throws ComponentInitializationException If component cannot be initialized.
	 * @throws ResolutionException              If attribute resolution fails.
	 */
	@Test
	public void testResolveAttributes_whenOneTeacherRole_shouldReturnValidUserDTO()
			throws ComponentInitializationException, ResolutionException, Exception {
		final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("teacher-1role-1attr.json",
				"restdc-min.xml");
		Assert.assertEquals(resolvedAttributes.size(), 17);
		Assert.assertEquals(resolvedAttributes.get(expectedResultAttribute).getValues().get(0).getNativeValue(),
				expectedOid);
		Assert.assertNull(resolvedAttributes.get("attr_" + RestDataConnector.ATTR_ID_LEARNER_ID));
		Assert.assertNull(resolvedAttributes.get(RestDataConnector.ATTR_ID_GROUP_LEVELS));
	}


	/**
	 * Tests {@link RestDataConnector} with minimum configuration, with one teacher
	 * role with group null for the user.
	 * 
	 * @throws ComponentInitializationException If component cannot be initialized.
	 * @throws ResolutionException              If attribute resolution fails.
	 */
	@Test
	public void testResolveAttributes_whenOneTeacherRoleWithGroupNull_shouldReturnValidUserDTO()
			throws ComponentInitializationException, ResolutionException, Exception {
		final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("teacher-1role-1attr2.json",
				"restdc-min.xml");
		Assert.assertEquals(resolvedAttributes.size(), 16);
		Assert.assertEquals(resolvedAttributes.get(expectedResultAttribute).getValues().get(0).getNativeValue(),
				expectedOid);
		Assert.assertNull(resolvedAttributes.get("attr_" + RestDataConnector.ATTR_ID_LEARNER_ID));
		Assert.assertNull(resolvedAttributes.get(RestDataConnector.ATTR_ID_GROUP_LEVELS));
		Assert.assertNull(resolvedAttributes.get(RestDataConnector.ATTR_ID_GROUPS));
	}

	/**
	 * Tests {@link RestDataConnector} with minimum configuration, with one teacher
	 * role with multiple null value attributes for the user.
	 * 
	 * @throws ComponentInitializationException If component cannot be initialized.
	 * @throws ResolutionException              If attribute resolution fails.
	 */
	@Test
	public void testResolveAttributes_whenOneTeacherRoleWithMultipleNullAttributes_shouldReturnValidUserDTO()
			throws ComponentInitializationException, ResolutionException, Exception {
		final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("teacher-1role-1attr3.json",
				"restdc-min.xml");
		Assert.assertEquals(resolvedAttributes.size(), 4);
		Assert.assertEquals(resolvedAttributes.get(expectedResultAttribute).getValues().get(0).getNativeValue(),
				expectedOid);
		Assert.assertNull(resolvedAttributes.get("attr_" + RestDataConnector.ATTR_ID_LEARNER_ID));
		Assert.assertNull(resolvedAttributes.get(RestDataConnector.ATTR_ID_GROUP_LEVELS));
		Assert.assertNull(resolvedAttributes.get(RestDataConnector.ATTR_ID_GROUPS));
		Assert.assertNull(resolvedAttributes.get(RestDataConnector.ATTR_ID_ROLES));
		Assert.assertNull(resolvedAttributes.get(RestDataConnector.ATTR_ID_MUNICIPALITIES));
	}

	/**
	 * Tests {@link RestDataConnector} with minimum configuration, with one student
	 * role for the user.
	 * 
	 * @throws ComponentInitializationException If component cannot be initialized.
	 * @throws ResolutionException              If attribute resolution fails.
	 */
	@Test
	public void testResolveAttributes_whenOneStudentRole_shouldReturnValidUserDTO()
			throws ComponentInitializationException, ResolutionException, Exception {
		final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("student-1role-1attr.json",
				"restdc-min.xml");
		Assert.assertEquals(resolvedAttributes.size(), 19);
		Assert.assertEquals(resolvedAttributes.get(expectedResultAttribute).getValues().get(0).getNativeValue(),
				expectedOid);

		final List<IdPAttributeValue> groupLevels = resolvedAttributes.get(RestDataConnector.ATTR_ID_GROUP_LEVELS)
				.getValues();
		Assert.assertTrue(verifyAttributeValueExists(groupLevels, "7"));
		Assert.assertEquals(resolvedAttributes.get("attr_" + RestDataConnector.ATTR_ID_LEARNER_ID).getValues().get(0)
				.getNativeValue(), expectedLearnerId);

		final List<IdPAttributeValue> schoolIds = resolvedAttributes.get(RestDataConnector.ATTR_ID_SCHOOL_IDS)
				.getValues();
		Assert.assertEquals(schoolIds.size(), 1);
		Assert.assertTrue(verifyAttributeValueExists(schoolIds, expectedSchoolId));

		final List<IdPAttributeValue> schoolInfos = resolvedAttributes.get(RestDataConnector.ATTR_ID_SCHOOL_INFOS)
				.getValues();
		Assert.assertEquals(schoolInfos.size(), 2);
		Assert.assertTrue(verifyAttributeValueExists(schoolInfos, expectedSchoolInfo));

		final List<IdPAttributeValue> educationProviderOids = resolvedAttributes
				.get(RestDataConnector.ATTR_ID_EDUCATION_PROVIDER_OID).getValues();
		Assert.assertEquals(educationProviderOids.size(), 1);
		Assert.assertTrue(verifyAttributeValueExists(educationProviderOids, expectedParentOid));

		final List<IdPAttributeValue> educationProviderNames = resolvedAttributes
				.get(RestDataConnector.ATTR_ID_EDUCATION_PROVIDER_NAME).getValues();
		Assert.assertEquals(educationProviderNames.size(), 1);
		Assert.assertTrue(verifyAttributeValueExists(educationProviderNames, expectedParentName));

		final List<IdPAttributeValue> educationProviderInfos = resolvedAttributes
				.get(RestDataConnector.ATTR_ID_EDUCATION_PROVIDER_INFOS).getValues();
		Assert.assertEquals(educationProviderOids.size(), 1);
		Assert.assertTrue(verifyAttributeValueExists(educationProviderInfos, expectedParentInfo));
		
		final List<IdPAttributeValue> learningMaterialCharge = resolvedAttributes
				.get(RestDataConnector.ATTR_ID_LEARNINGMATERIALSCHARGES).getValues();
		Assert.assertEquals(learningMaterialCharge.size(), 2);
		Assert.assertTrue(verifyAttributeValueExists(learningMaterialCharge, "1;12345"));
	}
	
	@Test
	public void testResolveAttributes_whenMultipleRoleAttributes_shouldReturnValidUserDTO()
			throws ComponentInitializationException, ResolutionException, Exception {
		//final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("student-1role-7attr.json",
		final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("student-MultipleRoleAttributes.json",
				"restdc-min.xml");
		//Assert.assertEquals(resolvedAttributes, "foo");
		Assert.assertEquals(resolvedAttributes.size(), 22);
		Assert.assertEquals(resolvedAttributes.get(expectedResultAttribute).getValues().get(0).getNativeValue(),
				expectedOid);

		final List<IdPAttributeValue> groupLevels = resolvedAttributes.get(RestDataConnector.ATTR_ID_GROUP_LEVELS)
				.getValues();
		Assert.assertTrue(verifyAttributeValueExists(groupLevels, "7"));
		Assert.assertEquals(resolvedAttributes.get("attr_" + RestDataConnector.ATTR_ID_LEARNER_ID).getValues().get(0)
				.getNativeValue(), expectedLearnerId);

		final List<IdPAttributeValue> schoolIds = resolvedAttributes.get(RestDataConnector.ATTR_ID_SCHOOL_IDS)
				.getValues();
		Assert.assertEquals(schoolIds.size(), 2);
		Assert.assertTrue(verifyAttributeValueExists(schoolIds, expectedSchoolId));

		final List<IdPAttributeValue> schoolInfos = resolvedAttributes.get(RestDataConnector.ATTR_ID_SCHOOL_INFOS)
				.getValues();		
		Assert.assertEquals(schoolInfos.size(), 4);
		Assert.assertTrue(verifyAttributeValueExists(schoolInfos, expectedSchoolInfo));

		final List<IdPAttributeValue> educationProviderOids = resolvedAttributes
				.get(RestDataConnector.ATTR_ID_EDUCATION_PROVIDER_OID).getValues();
		Assert.assertEquals(educationProviderOids.size(), 2);
		Assert.assertTrue(verifyAttributeValueExists(educationProviderOids, expectedParentOid));

		final List<IdPAttributeValue> educationProviderNames = resolvedAttributes
				.get(RestDataConnector.ATTR_ID_EDUCATION_PROVIDER_NAME).getValues();
		Assert.assertEquals(educationProviderNames.size(), 2);
		Assert.assertTrue(verifyAttributeValueExists(educationProviderNames, expectedParentName));

		final List<IdPAttributeValue> educationProviderInfos = resolvedAttributes
				.get(RestDataConnector.ATTR_ID_EDUCATION_PROVIDER_INFOS).getValues();
		Assert.assertEquals(educationProviderOids.size(), 2);
		Assert.assertTrue(verifyAttributeValueExists(educationProviderInfos, expectedParentInfo));
	}

	/**
	 * Tests {@link RestDataConnector} with minimum configuration, with one student
	 * role for the user.ß
	 * 
	 * @throws ComponentInitializationException If component cannot be initialized.
	 * @throws ResolutionException              If attribute resolution fails.
	 */
	@Test
	public void testResolveAttributes_whenOneStudentRoleWithInvalidGroupLevel_shouldReturnValidUserDTOWithoutGroupLevel()
			throws ComponentInitializationException, ResolutionException, Exception {
		final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes(
				"student-1role-1attr-invalidGroupLevel.json", "restdc-min.xml");
		Assert.assertEquals(resolvedAttributes.size(), 17);
		Assert.assertEquals(resolvedAttributes.get(expectedResultAttribute).getValues().get(0).getNativeValue(),
				expectedOid);
		Assert.assertNull(resolvedAttributes.get(RestDataConnector.ATTR_ID_GROUP_LEVELS));
		Assert.assertEquals(resolvedAttributes.get("attr_" + RestDataConnector.ATTR_ID_LEARNER_ID).getValues().get(0)
				.getNativeValue(), expectedLearnerId);
	}

	/**
	 * Tests {@link RestDataConnector} with minimum configuration, with one student
	 * role for the user.
	 * 
	 * @throws ComponentInitializationException If component cannot be initialized.
	 * @throws ResolutionException              If attribute resolution fails.
	 */
	@Test
	public void testResolveAttributes_whenOneStudentRoleWithSchoolMissing_shouldReturnValidUserDTOWithoutGroupLevel()
			throws ComponentInitializationException, ResolutionException, Exception {
		final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes(
				"student-1role-1attr-school-missing.json", "restdc-min.xml");
		Assert.assertEquals(resolvedAttributes.size(), 11);
		Assert.assertEquals(resolvedAttributes.get(expectedResultAttribute).getValues().get(0).getNativeValue(),
				expectedOid);
		Assert.assertNull(resolvedAttributes.get(RestDataConnector.ATTR_ID_SCHOOL_IDS));
		Assert.assertNull(resolvedAttributes.get(RestDataConnector.ATTR_ID_EDUCATION_PROVIDER_OID));
		Assert.assertNull(resolvedAttributes.get(RestDataConnector.ATTR_ID_EDUCATION_PROVIDER_NAME));
		final List<IdPAttributeValue> groups = resolvedAttributes.get(RestDataConnector.ATTR_ID_GROUPS).getValues();
		Assert.assertEquals(groups.size(), 1);
		Assert.assertEquals(groups.get(0).getNativeValue(), "7C");
		final List<IdPAttributeValue> groupLevels = resolvedAttributes.get(RestDataConnector.ATTR_ID_GROUP_LEVELS)
				.getValues();
		Assert.assertEquals(groupLevels.size(), 1);
		Assert.assertEquals(groupLevels.get(0).getNativeValue(), "7");
		Assert.assertEquals(resolvedAttributes.get("attr_" + RestDataConnector.ATTR_ID_LEARNER_ID).getValues().get(0)
				.getNativeValue(), expectedLearnerId);
	}

	/**
	 * Tests {@link RestDataConnector} with minimum configuration, with two teacher
	 * roles for the user.
	 * 
	 * @throws ComponentInitializationException If component cannot be initialized.
	 * @throws ResolutionException              If attribute resolution fails.
	 */
	@Test
	public void testResolveAttributes_whenTwoTeacherRolesTwoAttributes_shouldReturnValidUserDTO()
			throws ComponentInitializationException, ResolutionException, Exception {
		final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("teacher-2role-2attr.json",
				"restdc-min.xml");
		Assert.assertEquals(resolvedAttributes.size(), 18);
		Assert.assertEquals(resolvedAttributes.get(expectedResultAttribute).getValues().get(0).getNativeValue(),
				expectedOid);
		Assert.assertNull(resolvedAttributes.get(RestDataConnector.ATTR_ID_GROUP_LEVELS));
		Assert.assertNull(resolvedAttributes.get(RestDataConnector.ATTR_ID_LEARNER_ID));
	}

	/**
	 * Tests {@link RestDataConnector} with minimum configuration, with two student
	 * roles for the user.
	 * 
	 * @throws ComponentInitializationException If component cannot be initialized.
	 * @throws ResolutionException              If attribute resolution fails.
	 */
	@Test
	public void testResolveAttributes_whenTwoStudentRoles_shouldReturnValidUserDTOWithStudentRole()
			throws ComponentInitializationException, ResolutionException, Exception {
		final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("student-2role-2attr.json",
				"restdc-min.xml");
		//Assert.assertEquals(resolvedAttributes, "foo");
		Assert.assertEquals(resolvedAttributes.size(), 20);
		Assert.assertEquals(resolvedAttributes.get(expectedResultAttribute).getValues().get(0).getNativeValue(),
				expectedOid);

		final List<IdPAttributeValue> groupLevels = resolvedAttributes.get(RestDataConnector.ATTR_ID_GROUP_LEVELS)
				.getValues();
		Assert.assertEquals(groupLevels.size(), 1);
		Assert.assertTrue(verifyAttributeValueExists(groupLevels, "7"));

		final List<IdPAttributeValue> educationProviderOids = resolvedAttributes
				.get(RestDataConnector.ATTR_ID_EDUCATION_PROVIDER_OID).getValues();
		Assert.assertEquals(educationProviderOids.size(), 2);
		Assert.assertTrue(verifyAttributeValueExists(educationProviderOids, expectedParentOid, expectedParentOid2));

		final List<IdPAttributeValue> educationProviderNames = resolvedAttributes
				.get(RestDataConnector.ATTR_ID_EDUCATION_PROVIDER_NAME).getValues();
		Assert.assertEquals(educationProviderNames.size(), 2);
		Assert.assertTrue(verifyAttributeValueExists(educationProviderNames, expectedParentName, expectedParentName2));
		
		final List<IdPAttributeValue> learningMaterialCharge = resolvedAttributes
				.get(RestDataConnector.ATTR_ID_LEARNINGMATERIALSCHARGES).getValues();
		Assert.assertEquals(learningMaterialCharge.size(), 4);
		Assert.assertTrue(verifyAttributeValueExists(learningMaterialCharge, "0;12345"));
		Assert.assertTrue(verifyAttributeValueExists(learningMaterialCharge, "1;23456"));
	}
	
	/**
	 * Tests {@link RestDataConnector} with minimum configuration, with two student
	 * roles for the user.
	 * 
	 * @throws ComponentInitializationException If component cannot be initialized.
	 * @throws ResolutionException              If attribute resolution fails.
	 */
	@Test
	public void testResolveAttributes_whenTwoStudentRoles_shouldReturnValidUserDTOWithStudentRole_new()
			throws ComponentInitializationException, ResolutionException, Exception {
		final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("student-2role-2attr_new.json",
				"restdc-min.xml");
		//Assert.assertEquals(resolvedAttributes, "foo");
		Assert.assertEquals(resolvedAttributes.size(), 21);		
		Assert.assertEquals(resolvedAttributes.get(expectedResultAttribute).getValues().get(0).getNativeValue(),expectedOid);

		final List<IdPAttributeValue> schoolIds = resolvedAttributes.get(RestDataConnector.ATTR_ID_SCHOOL_IDS)
				.getValues();
		Assert.assertEquals(schoolIds.size(), 2);
		Assert.assertTrue(verifyAttributeValueExists(schoolIds, "12345", "23456"));
		
		final List<IdPAttributeValue> groupLevels = resolvedAttributes.get(RestDataConnector.ATTR_ID_GROUP_LEVELS)
				.getValues();
		Assert.assertEquals(groupLevels.size(), 1);
		Assert.assertTrue(verifyAttributeValueExists(groupLevels, "7"));
		
		final List<IdPAttributeValue> groups = resolvedAttributes.get(RestDataConnector.ATTR_ID_GROUPS)
				.getValues();
		Assert.assertEquals(groups.size(), 1);
		Assert.assertTrue(verifyAttributeValueExists(groups, "7C"));

		final List<IdPAttributeValue> educationProviderOids = resolvedAttributes
				.get(RestDataConnector.ATTR_ID_EDUCATION_PROVIDER_OID).getValues();
		Assert.assertEquals(educationProviderOids.size(), 2);
		Assert.assertTrue(verifyAttributeValueExists(educationProviderOids, expectedParentOid, expectedParentOid2));

		final List<IdPAttributeValue> educationProviderNames = resolvedAttributes
				.get(RestDataConnector.ATTR_ID_EDUCATION_PROVIDER_NAME).getValues();
		Assert.assertEquals(educationProviderNames.size(), 2);
		Assert.assertTrue(verifyAttributeValueExists(educationProviderNames, expectedParentName, expectedParentName2));
	}

	@Test
	public void testResolveAttributes_whenTestiu_00001_shouldReturnValidUserDTO()
			throws ComponentInitializationException, ResolutionException, Exception {
		final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("testiu_00001.json",
				"restdc-min.xml");
		Assert.assertEquals(resolvedAttributes.size(), 24);
		Assert.assertEquals(resolvedAttributes.get(RestDataConnector.ATTR_ID_STRUCTURED_ROLES_WID).getValues().get(0).getNativeValue(),
				"Testilä;99904;1D;Oppilas");
		Assert.assertNull(resolvedAttributes.get(RestDataConnector.ATTR_ID_LEARNINGMATERIALSCHARGES));
		//Assert.assertNull(resolvedAttributes.get("attr_" + RestDataConnector.ATTR_ID_LEARNER_ID));
		//Assert.assertNull(resolvedAttributes.get(RestDataConnector.ATTR_ID_GROUP_LEVELS));
	}
	
	@Test
	public void testResolveAttributes_whenTestiu_00001_2_shouldReturnValidUserDTO()
			throws ComponentInitializationException, ResolutionException, Exception {
		final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("testiu_00001_2.json",
				"restdc-min.xml");
		//Assert.assertEquals(resolvedAttributes, "foo");
		Assert.assertEquals(resolvedAttributes.size(), 26);
		Assert.assertEquals(resolvedAttributes.get(RestDataConnector.ATTR_ID_STRUCTURED_ROLES_WID).getValues().get(0).getNativeValue(),
				"Testilä;99904;1D;Oppilas");
		Assert.assertEquals(resolvedAttributes
				.get(RestDataConnector.ATTR_ID_LEARNINGMATERIALSCHARGES).getValues().get(0).getNativeValue(), "1;99904");
		//Assert.assertNull(resolvedAttributes.get("attr_" + RestDataConnector.ATTR_ID_LEARNER_ID));
		//Assert.assertNull(resolvedAttributes.get(RestDataConnector.ATTR_ID_GROUP_LEVELS));
	}
	
	
	@Test
	public void testResolveAttributes_whenTestu_00071_shouldReturnValidUserDTO()
			throws ComponentInitializationException, ResolutionException, Exception {
		final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("testiu_00071.json",
				"restdc-min.xml");
	
		Assert.assertEquals(resolvedAttributes.size(), 20);
		Assert.assertEquals(resolvedAttributes.get(expectedResultAttribute).getValues().get(0).getNativeValue(),
				"MPASSOID.6dfaba3e247015501de9c129a1a70926e0fa8f7f");

		final List<IdPAttributeValue> structuredRoleWids = resolvedAttributes.get(RestDataConnector.ATTR_ID_STRUCTURED_ROLES_WID)
				.getValues();
		final List<IdPAttributeValue> structuredRolesWithParentOid = resolvedAttributes.get(RestDataConnector.ATTR_ID_STRUCTURED_ROLES_WITH_PARENT_OID)
				.getValues();
		// Only the first school group is populated. Test users first group is empty
		Assert.assertNull(resolvedAttributes.get(RestDataConnector.ATTR_ID_GROUPS));
		Assert.assertEquals(structuredRoleWids.get(0).getNativeValue(), "Testilä;99904;;Opettaja");
		Assert.assertEquals(structuredRoleWids.get(1).getNativeValue(), "Testilä;99905;4B;Sijaisopettaja");
		Assert.assertEquals(structuredRoleWids.get(2).getNativeValue(), "Testilä;99906;6C;Sijaisopettaja");
		Assert.assertEquals(structuredRolesWithParentOid.size(), 3);
		Assert.assertEquals(structuredRolesWithParentOid.get(0).getNativeValue(), "1.2.246.562.10.45678901237;99904;;Opettaja;2;;");
		Assert.assertEquals(structuredRolesWithParentOid.get(1).getNativeValue(), "1.2.246.562.10.45678901237;99905;4B;Sijaisopettaja;5;;");
		Assert.assertEquals(structuredRolesWithParentOid.get(2).getNativeValue(), "1.2.246.562.10.78901234567;99906;6C;Sijaisopettaja;5;;");
	}
	
	@Test
	public void testResolveAttributes_whenStudentWithMultivalueAttributes_shouldReturnValidUserDTO()
			throws ComponentInitializationException, ResolutionException, Exception {
		final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("student-MultivalueAttributes.json",
				"restdc-min.xml");
		//Assert.assertEquals(resolvedAttributes, "foo");
		Assert.assertEquals(resolvedAttributes.size(), 26);
		Assert.assertEquals(resolvedAttributes.get(RestDataConnector.ATTR_ID_STRUCTURED_ROLES_WID).getValues().get(0).getNativeValue(),
				"Testilä;99904;1D;Oppilas");
		Assert.assertEquals(resolvedAttributes.get(RestDataConnector.ATTR_ID_STRUCTURED_ROLES_WID).getValues().get(1).getNativeValue(),
				"Testilä;99905;;Oppilas");
		Assert.assertEquals(resolvedAttributes.get(RestDataConnector.ATTR_ID_STRUCTURED_ROLES_WID).getValues().get(2).getNativeValue(),
				"Testilä;99906;;Oppilas");
		Assert.assertEquals(resolvedAttributes
				.get(RestDataConnector.ATTR_ID_LEARNINGMATERIALSCHARGES).getValues().get(0).getNativeValue(), "1;99904");
		Assert.assertEquals(resolvedAttributes
				.get(RestDataConnector.ATTR_ID_LEARNINGMATERIALSCHARGES).getValues().get(1).getNativeValue(), "0;99905");
		Assert.assertEquals(resolvedAttributes
				.get(RestDataConnector.ATTR_ID_LEARNINGMATERIALSCHARGES).getValues().get(2).getNativeValue(), "1;99906");
	}
	
	@Test
	public void testResolveAttributes_whenUserWithMultivalueAttributes_v2_shouldReturnValidUserDTO()
			throws ComponentInitializationException, ResolutionException, Exception {
		final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("student-MultivalueAttributes_2.json",
				"restdc-min.xml");
		//Assert.assertEquals(resolvedAttributes, "foo");
		Assert.assertEquals(resolvedAttributes.size(), 26);
		Assert.assertEquals(resolvedAttributes.get(RestDataConnector.ATTR_ID_STRUCTURED_ROLES_WID).getValues().get(0).getNativeValue(),
				"Testilä;99904;1D;Oppilas");
		Assert.assertEquals(resolvedAttributes.get(RestDataConnector.ATTR_ID_STRUCTURED_ROLES_WID).getValues().get(1).getNativeValue(),
				"Testilä;99905;;Opettaja");
		Assert.assertEquals(resolvedAttributes.get(RestDataConnector.ATTR_ID_STRUCTURED_ROLES_WID).getValues().get(2).getNativeValue(),
				"Testilä;99906;;Oppilas");
		Assert.assertEquals(resolvedAttributes
				.get(RestDataConnector.ATTR_ID_LEARNINGMATERIALSCHARGES).getValues().get(0).getNativeValue(), "1;99904");
		Assert.assertEquals(resolvedAttributes
				.get(RestDataConnector.ATTR_ID_LEARNINGMATERIALSCHARGES).getValues().get(1).getNativeValue(), "0;99906");
	}
	
	
	/**
	 * Tests {@link RestDataConnector} resolver attributes for test users.
	 * 
	 * It's poosible to test only one expected value for multivalue attribute.
	 */
	@Test
	public void testResolveAttributes_whenTestUser_shouldReturnValidUserDTO()
			throws ComponentInitializationException, ResolutionException, Exception {
		
		List<Pair<String, HashMap<String,Object>>> testUsers = new ArrayList<>();
	
		testUsers.add(new Pair<>("testiu_00001", new HashMap<>()));
		testUsers.get(0).getSecond().put("expectedSize",24);		
		testUsers.get(0).getSecond().put(RestDataConnector.ATTR_ID_USERNAME, "MPASSOID.3e62d573058fa45216cd011ec67aa31552750baa");
		testUsers.get(0).getSecond().put("roleSize", 1);
		
		testUsers.add(new Pair<>("testiu_00070", new HashMap<>()));
		testUsers.get(1).getSecond().put("expectedSize",19);
		testUsers.get(1).getSecond().put(RestDataConnector.ATTR_ID_USERNAME, "MPASSOID.7ac492de994ae2ef6d6278ae3ff0150c6545e27e");
		testUsers.get(1).getSecond().put(RestDataConnector.ATTR_ID_SCHOOL_IDS, "99906");
		testUsers.get(1).getSecond().put("schoolIdsSize", 3);

		testUsers.add(new Pair<>("testiu_00071", new HashMap<>()));
		testUsers.get(2).getSecond().put("expectedSize",20);
		testUsers.get(2).getSecond().put(RestDataConnector.ATTR_ID_USERNAME, "MPASSOID.6dfaba3e247015501de9c129a1a70926e0fa8f7f");
		testUsers.get(2).getSecond().put(RestDataConnector.ATTR_ID_STRUCTURED_ROLES_WITH_PARENT_OID, "1.2.246.562.10.45678901237;99904;;Opettaja;2;;");
		testUsers.get(2).getSecond().put("roleSize", 3);

		testUsers.add(new Pair<>("testiu_00060", new HashMap<>()));
		testUsers.get(3).getSecond().put("expectedSize",7);
		testUsers.get(3).getSecond().put(RestDataConnector.ATTR_ID_SCHOOL_IDS, null);
		testUsers.get(3).getSecond().put(RestDataConnector.ATTR_ID_USERNAME, "MPASSOID.d41117ccc3d8424293b121163d1ee2f61ffc7513");

		for (Pair<String, HashMap<String,Object>> user : testUsers) {
			
			final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes(user.getFirst() + ".json",
					"restdc-min.xml");
			
			Map<String,Object> expectedAttributes = user.getSecond();
			
			expectedAttributes.forEach((k,v) -> {
			
				if (v == null) {
					Assert.assertNull(resolvedAttributes.get(k));
				} else if (k.toLowerCase().endsWith("size")) {
					
					// Fails if key with size is defined for testUsers but not here.
					switch (k) {
						case "expectedSize":
							Assert.assertEquals(resolvedAttributes.size(), user.getSecond().get("expectedSize"));
							break;
						case "roleSize":
							Assert.assertEquals(resolvedAttributes.get(RestDataConnector.ATTR_ID_STRUCTURED_ROLES_WITH_PARENT_OID).getValues().size(), user.getSecond().get(k));
							break;
						case "schoolIdsSize":
							Assert.assertEquals(resolvedAttributes.get(RestDataConnector.ATTR_ID_SCHOOL_IDS).getValues().size(), user.getSecond().get(k));
							break;
						default:
							Assert.assertTrue(false, user.getFirst() + " has an key for attribute size test but the key is not defined in test cases. AssertTrue:");
					}
				} else {
					String expectedValue = user.getSecond().get(k).toString();
					Assert.assertTrue(verifyAttributeValueExists(resolvedAttributes.get(k).getValues(), expectedValue), user.getFirst() + " attribute " + k + " failed with expected value: " + expectedValue + ". AssertTrue:");
				}
			});
		}
	}

	@Test
	public void testResolveAttributes_whenOfficeCodeAndwhenOneStudentRole_shouldReturnValidUserDTO()
			throws ComponentInitializationException, ResolutionException, Exception {
		final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("student-1role-1attr-officeCode.json",
				"restdc-min.xml");

			
		Assert.assertEquals(resolvedAttributes.size(), 20);
		Assert.assertEquals(resolvedAttributes.get(expectedResultAttribute).getValues().get(0).getNativeValue(),
				expectedOid);

		final List<IdPAttributeValue> groupLevels = resolvedAttributes.get(RestDataConnector.ATTR_ID_GROUP_LEVELS)
				.getValues();
		Assert.assertTrue(verifyAttributeValueExists(groupLevels, "7"));
		Assert.assertEquals(resolvedAttributes.get("attr_" + RestDataConnector.ATTR_ID_LEARNER_ID).getValues().get(0)
				.getNativeValue(), expectedLearnerId);

		final List<IdPAttributeValue> schoolOids = resolvedAttributes.get(RestDataConnector.ATTR_ID_SCHOOL_OIDS)
				.getValues();
		Assert.assertEquals(schoolOids.size(), 1);
		
		Assert.assertTrue(verifyAttributeValueExists(schoolOids, expectedSchoolOid));

		final List<IdPAttributeValue> schoolInfos = resolvedAttributes.get(RestDataConnector.ATTR_ID_SCHOOL_INFOS)
				.getValues();
		Assert.assertEquals(schoolInfos.size(), 3);
		Assert.assertTrue(verifyAttributeValueExists(schoolInfos, expectedSchoolInfo));

		final List<IdPAttributeValue> educationProviderOids = resolvedAttributes
				.get(RestDataConnector.ATTR_ID_EDUCATION_PROVIDER_OID).getValues();
		Assert.assertEquals(educationProviderOids.size(), 1);
		Assert.assertTrue(verifyAttributeValueExists(educationProviderOids, expectedParentOid));

		final List<IdPAttributeValue> educationProviderNames = resolvedAttributes
				.get(RestDataConnector.ATTR_ID_EDUCATION_PROVIDER_NAME).getValues();
		Assert.assertEquals(educationProviderNames.size(), 1);
		Assert.assertTrue(verifyAttributeValueExists(educationProviderNames, expectedParentName));

		final List<IdPAttributeValue> educationProviderInfos = resolvedAttributes
				.get(RestDataConnector.ATTR_ID_EDUCATION_PROVIDER_INFOS).getValues();
		Assert.assertEquals(educationProviderOids.size(), 1);
		Assert.assertTrue(verifyAttributeValueExists(educationProviderInfos, expectedParentInfo));
		
		final List<IdPAttributeValue> learningMaterialCharge = resolvedAttributes
				.get(RestDataConnector.ATTR_ID_LEARNINGMATERIALSCHARGES).getValues();
		Assert.assertEquals(learningMaterialCharge.size(), 2);
		Assert.assertTrue(verifyAttributeValueExists(learningMaterialCharge, "1;12345"));
	}
	
	/**
	 * Verifies that all the given values are found from the given list of
	 * attributes.
	 * 
	 * @param output The list of attributes whose contents are verified.
	 * @param input  The values whose existence is verified from the list of
	 *               attributes.
	 * @return True if all values were found, false otherwise.
	 */
	protected boolean verifyAttributeValueExists(final List<IdPAttributeValue> output, String... input) {
		for (final String inputValue : input) {
			for (final IdPAttributeValue value : output) {
				if (inputValue.equals(value.getDisplayValue())) {
					return true;
				}
			}
		}
		return false;
	}
	
	/**
	 * Verifies that all the given values are found from the given list of
	 * attributes.
	 * 
	 * @param output The list of attributes whose contents are verified.
	 * @param input  The values whose existence is verified from the list of
	 *               attributes.
	 * @return True if all values were found, false otherwise.
	 */
/*	protected boolean verifyAttributeValueExists(final List<IdPAttributeValue> output, String... input) {
		for (final String inputValue : input) {
			boolean found = false;
			for (final IdPAttributeValue value : output) {
				if (inputValue.equals(value.getNativeValue().toString())) {
					found = true;
					break;
				}
			}
			if (!found) {
				return false;
			}
		}
		return true;
	}*/

	/**
	 * Tests wheter dataconnector settings are valid.
	 * 
	 * @param dataConnector The data connector.
	 * @param disregard     Whether TLS should be disregarded or not.
	 * @param prefix        The attribute prefix.
	 */
	protected void testSettings(final RestDataConnector dataConnector, final boolean disregard, final String prefix) {
		Assert.assertEquals(dataConnector.getId(), expectedId);
		Assert.assertEquals(dataConnector.getEndpointUrl(), expectedEndpointUrl);
		Assert.assertEquals(dataConnector.getToken(), expectedToken);
		Assert.assertEquals(dataConnector.isDisregardTLSCertificate(), disregard);
		Assert.assertEquals(dataConnector.getResultAttributePrefix(), prefix);
		Assert.assertNotNull(dataConnector.getHttpClientBuilder());
	}

	@Test
	public void testPrincipals_whenUserHaveOneAttributeInAllRoleAttributes_shouldReturnValidUserDTO() throws Exception {
		Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("restdc-full.xml",
				new ShibAttributePrincipal("uid", "uidValue"), 
				new ShibAttributePrincipal("schoolId", expectedSchoolId),
				new ShibAttributePrincipal("groupLevel", "7"), 
				new ShibAttributePrincipal("group", "7C"),
				new ShibAttributePrincipal("role", "Oppilas"),
				new ShibAttributePrincipal("learningMaterialsCharge", "1")
				);
		//Assert.assertEquals(resolvedAttributes, "foo");
		Assert.assertEquals(resolvedAttributes.keySet().size(), 15);
		Assert.assertNotNull(resolvedAttributes.get("testingPrefixusername").getValues().get(0).getNativeValue());
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_SCHOOL_CODES).getValues().get(0).getNativeValue(), expectedSchoolId);
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_GRADE).getValues().get(0).getNativeValue(), "7");
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_SCHOOL_ROLES).getValues().get(0).getNativeValue(), "Oppilas");
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_CLASSES).getValues().get(0).getNativeValue(), "7C");
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_MUNICIPALITY_CODE).getValues().get(0).getNativeValue(), "007");
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_MUNICIPALITIES).getValues().get(0).getNativeValue(), "Helsinki");
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_LEARNINGMATERIALSCHARGES).getValues().get(0).getNativeValue(), "1");
	}
	
	@Test
	public void testPrincipals_whenUserHaveOneAttributeInAllRoleAttributes_2_shouldReturnValidUserDTO() throws Exception {
		Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("restdc-full.xml",
				new ShibAttributePrincipal("uid", "uidValue"), 
				new ShibAttributePrincipal("schoolId", "99900"),
				new ShibAttributePrincipal("groupLevel", "7"), 
				new ShibAttributePrincipal("group", "7C"),
				new ShibAttributePrincipal("role", "Oppilas")
				);
		//Assert.assertEquals(resolvedAttributes, "foo");
		Assert.assertEquals(resolvedAttributes.keySet().size(), 14);
		Assert.assertNotNull(resolvedAttributes.get("testingPrefixusername").getValues().get(0).getNativeValue());
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_SCHOOL_CODES).getValues().get(0).getNativeValue(), "99900");
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_GRADE).getValues().get(0).getNativeValue(), "7");
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_SCHOOL_ROLES).getValues().get(0).getNativeValue(), "Oppilas");
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_CLASSES).getValues().get(0).getNativeValue(), "7C");
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_MUNICIPALITY_CODE).getValues().get(0).getNativeValue(), "007");
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_MUNICIPALITIES).getValues().get(0).getNativeValue(), "Helsinki");
	}
	
	@Test
	public void testPrincipals_whenUserHaveMultipleValueAttributeInAllRoleAttributes_shouldReturnValidUserDTO() throws Exception {
		Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("restdc-full.xml",
				new ShibAttributePrincipal("uid", "uidValue"), 
				new ShibAttributePrincipal("schoolId", expectedSchoolId + ";" + expectedSchoolId2),
				new ShibAttributePrincipal("groupLevel", "7"), 
				new ShibAttributePrincipal("group", "7C;8A"),
				new ShibAttributePrincipal("role", "Oppilas"),
				new ShibAttributePrincipal("learningMaterialsCharge", "1")
				);
		//Assert.assertEquals(resolvedAttributes, "foo");
		Assert.assertEquals(resolvedAttributes.keySet().size(), 15);
		Assert.assertNotNull(resolvedAttributes.get("testingPrefixusername").getValues().get(0).getNativeValue());
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_SCHOOL_CODES).getValues().get(0).getNativeValue(), expectedSchoolId + ";" + expectedSchoolId2);
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_GRADE).getValues().get(0).getNativeValue(), "7");
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_SCHOOL_ROLES).getValues().get(0).getNativeValue(), "Oppilas");
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_CLASSES).getValues().get(0).getNativeValue(), "7C;8A");
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_MUNICIPALITY_CODE).getValues().get(0).getNativeValue(), "007");
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_MUNICIPALITIES).getValues().get(0).getNativeValue(), "Helsinki");
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_LEARNINGMATERIALSCHARGES).getValues().get(0).getNativeValue(), "1");
	}
	
	@Test
	public void testPrincipals_whenUserHaveMultipleValueAttributeInAllRoleAttributesV2_shouldReturnValidUserDTO() throws Exception {
		Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("restdc-full.xml",
				new ShibAttributePrincipal("uid", "uidValue"), 
				new ShibAttributePrincipal("schoolId", expectedSchoolId + ";" + expectedSchoolId2),
				new ShibAttributePrincipal("groupLevel", "7"), 
				new ShibAttributePrincipal("group", "7C;8A"),
				new ShibAttributePrincipal("role", "Opettaja"));
		//Assert.assertEquals(resolvedAttributes, "foo");
		Assert.assertEquals(resolvedAttributes.keySet().size(), 14);
		Assert.assertNotNull(resolvedAttributes.get("testingPrefixusername").getValues().get(0).getNativeValue());
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_SCHOOL_CODES).getValues().get(0).getNativeValue(), expectedSchoolId + ";" + expectedSchoolId2);
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_GRADE).getValues().get(0).getNativeValue(), "7");
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_SCHOOL_ROLES).getValues().get(0).getNativeValue(), "Opettaja");
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_CLASSES).getValues().get(0).getNativeValue(), "7C;8A");
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_MUNICIPALITY_CODE).getValues().get(0).getNativeValue(), "007");
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_MUNICIPALITIES).getValues().get(0).getNativeValue(), "Helsinki");
	}
	

	@Test
	public void testPrincipals() throws Exception {
		Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("restdc-full.xml",
				new ShibAttributePrincipal("uid", "uidValue"),
				new ShibAttributePrincipal("schoolId", expectedSchoolId),
				new ShibAttributePrincipal("role", "Opettaja"));
		//Assert.assertEquals(resolvedAttributes, "foo");
		Assert.assertEquals(resolvedAttributes.keySet().size(), 10);
		Assert.assertNotNull(resolvedAttributes.get("testingPrefixusername").getValues().get(0).getNativeValue());
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_SCHOOL_CODES).getValues().get(0).getNativeValue(), expectedSchoolId);
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_SCHOOL_ROLES).getValues().get(0).getNativeValue(), "Opettaja");
		Assert.assertEquals(resolvedAttributes.get("testingPrefix"  + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_MUNICIPALITY_CODE).getValues().get(0).getNativeValue(), "007");
		Assert.assertEquals(resolvedAttributes.get("testingPrefix" + RestDataConnector.ATTR_PREFIX + RestDataConnector.ATTR_ID_MUNICIPALITIES).getValues().get(0).getNativeValue(), "Helsinki");
	}
	
	/**
	 * Resolves the attributes with the given settings and default mock schools.
	 * 
	 * @param userJson          The User object response simulation from the REST
	 *                          endpoint.
	 * @param connectorSettings The settings.
	 * @return The map of resolved attributes.
	 * @throws Exception
	 */
	protected Map<String, IdPAttribute> resolveAttributes(String userJson, String connectorSettings) throws Exception {
		
		School mockSchool = new School(expectedSchoolId, expectedSchoolName, expectedSchoolOid,null,null,expectedParentOid, expectedParentName,"organisaatiotyyppi_02");
		School mockSchool2 = new School(expectedSchoolId2, expectedSchoolName2, expectedSchoolOid2,null,null, expectedParentOid2, expectedParentName2,"organisaatiotyyppi_02");
		
		School mockSchool3 = new School("99900", "Demolan koulu", "1.2.246.562.10.12345678907", "Demolan kunta");
		School mockSchool4 = new School("99901", "Demolan ala-asteu", "1.2.246.562.10.12345678907", "Demolan kunta");
		School mockSchool5 = new School("99904", "Testilän koulu", "1.2.246.562.10.45678901237", "Testilän kunta");
		School mockSchool6 = new School("99905", "Testilän ala-aste", "1.2.246.562.10.45678901237", "Testilän kunta");
		School mockSchool7 = new School("99906", "Esimerkkilän peruskoulu", "1.2.246.562.10.78901234567", "Esimerkkilän kunta");
		School office1 = new School(expectedOfficeOid, expectedOfficeName, expectedOfficeOid,null,null, expectedSchoolOid, expectedSchoolName, "organisaatiotyyppi_08");
		School office2 = new School(expectedOfficeOid2, expectedOfficeName2, expectedOfficeOid2,null,null, expectedSchoolOid2, expectedSchoolName2, "organisaatiotyyppi_08");
		return resolveAttributes(userJson, connectorSettings, mockSchool, mockSchool2, mockSchool3, mockSchool4, mockSchool5, mockSchool6, mockSchool7,office1,office2);
	}
	
	/**
	 * Resolves the attributes with the given settings.
	 * 
	 * @param userJson          The User object response simulation from the REST endpoint.
	 * @param connectorSettings The settings.
	 * @param mockSchools List of the mocked schools.
	 * @return The map of resolved attributes.
	 * @throws Exception
	 */
	protected Map<String, IdPAttribute> resolveAttributes(String userJson, String connectorSettings, School... mockSchools) throws Exception {
		HttpClientBuilder mockBuilder = initializeMockBuilder(userJson);
		final RestDataConnector dataConnector = RestDataConnectorParserTest.initializeDataConnector(connectorSettings);
		final AttributeResolutionContext context = TestSources.createResolutionContext(TestSources.PRINCIPAL_ID,
				TestSources.IDP_ENTITY_ID, TestSources.SP_ENTITY_ID);
		final AttributeResolverWorkContext workContext = context.getSubcontext(AttributeResolverWorkContext.class,
				false);
		recordWorkContextAttribute(expectedHookAttribute, "hookAttributeValue", workContext);
		recordWorkContextAttribute(expectedIdpId, "idpIdValue", workContext);
		RestDataConnector mockConnector = Mockito.spy(dataConnector);
		Mockito.doReturn(mockBuilder).when(mockConnector).getHttpClientBuilder();

		//School mockSchool = new School(expectedSchoolId, expectedSchoolName, expectedParentOid, expectedParentName);
		for (final School mockSchool : mockSchools) {
			if(mockSchool.getOid()!=null) {
				Mockito.when(mockConnector.findSchool(eq(mockSchool.getOid()), anyString())).thenReturn(mockSchool);			
			}
			if(mockSchool.getId()!=null) {
				Mockito.when(mockConnector.findSchool(eq(mockSchool.getId()), anyString())).thenReturn(mockSchool);			
			}
			
		}

		//School mockSchool2 = new School(expectedSchoolId2, expectedSchoolName2, expectedParentOid2,
		//		expectedParentName2);
		//Mockito.when(mockConnector.getSchool(eq(expectedSchoolId2), anyString())).thenReturn(mockSchool2);

		// TODO: Is it ok to remove from here? Settings are tested elsewhere and with it it's not possible to test with different connection setting because discard TLS cert has static value in here.
		//testSettings(dataConnector, false, "");
		return mockConnector.doResolve(context, workContext);
	}

	protected Map<String, IdPAttribute> resolveAttributes(String connectorSettings, Principal... principals)
			throws Exception {
		final RestDataConnector dataConnector = RestDataConnectorParserTest.initializeDataConnector(connectorSettings);
		final AttributeResolutionContext context = TestSources.createResolutionContext(TestSources.PRINCIPAL_ID,
				TestSources.IDP_ENTITY_ID, TestSources.SP_ENTITY_ID);
		final AttributeResolverWorkContext workContext = context.getSubcontext(AttributeResolverWorkContext.class,
				false);
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
		ClassicHttpResponse mockResponse = Mockito.mock(ClassicHttpResponse.class);
		//StatusLine mockStatusLine = Mockito.mock(StatusLine.class);
		//Mockito.doReturn(200).when(mockStatusLine).getStatusCode();
		Mockito.when(mockResponse.getCode()).thenReturn(200);
		HttpClient mockClient = Mockito.mock(HttpClient.class);
		HttpEntity mockEntity = Mockito.mock(HttpEntity.class);
		Mockito.when(mockResponse.getEntity()).thenReturn(mockEntity);
		Mockito.when(mockEntity.getContent()).thenReturn(getUserObjectStream(userJson));
		Mockito.when(
				mockClient.executeOpen(ArgumentMatchers.any(),ArgumentMatchers.any(ClassicHttpRequest.class), ArgumentMatchers.any(HttpContext.class)))
				.thenReturn(mockResponse);
		Mockito.when(mockBuilder.buildClient()).thenReturn(mockClient);
		return mockBuilder;
	}

	/**
	 * Helper method to point JSON file declaration to correct directory and convert
	 * it to {@link InputStream}.
	 * 
	 * @param userJson The JSON filename, without directory prefix.
	 * @return The stream corresponding to the file.
	 * @throws Exception
	 */
	protected InputStream getUserObjectStream(String userJson) throws Exception {
		return new FileInputStream("src/test/resources/fi/mpass/shibboleth/attribute/resolver/data/" + userJson);
	}

	/**
	 * Helper method for recording attribute name and value to
	 * {@link AttributeResolverWorkContext}.
	 * 
	 * @param attributeName  The attribute name to be recorded.
	 * @param attributeValue The attribute value to be recorded.
	 * @param workContext    The target {@link AttributeResolverWorkContext}.
	 * @throws ComponentInitializationException If component cannot be initialized.
	 * @throws ResolutionException              If attribute recording fails.
	 */
	protected void recordWorkContextAttribute(final String attributeName, final String attributeValue,
			final AttributeResolverWorkContext workContext)
			throws ComponentInitializationException, ResolutionException {
		final AttributeDefinition definition = TestSources.populatedStaticAttribute(attributeName, 1);
		workContext.recordAttributeDefinitionResolution(definition, populateAttribute(attributeName, attributeValue));
	}

	/**
	 * Helper method for populating a String-valued attribute with given parameters.
	 * 
	 * @param attributeName  The attribute name to be populated.
	 * @param attributeValue The attribute value.
	 * @return The populated {@link IdPAttribute}.
	 */
	protected IdPAttribute populateAttribute(final String attributeName, final String attributeValue) {
		IdPAttribute idpAttribute = new IdPAttribute(attributeName);
		final List<IdPAttributeValue> values = new ArrayList<>();
		values.add(new StringAttributeValue(attributeValue));
		idpAttribute.setValues(values);
		return idpAttribute;
	}

	@Test
	public void testGetSchool_whenNull_thenShouldReturnNull() {
		Assert.assertNull(new RestDataConnector().findSchool(null, null));
	}

	@Test
	public void testGetSchool_whenEmpty_thenShouldReturnNull() {
		Assert.assertNull(new RestDataConnector().findSchool("", null));
	}

	@Test
	public void testGetSchool_whenNonNumericSchoolId_thenShouldReturnNull() {
		Assert.assertNull(new RestDataConnector().findSchool("mock", null));
	}

	@Test
	public void testGetSchool_whenTooLongSchoolId_thenShouldReturnNull() {
		Assert.assertNull(new RestDataConnector().findSchool("1234567", null));
	}

	@Test
	public void testSchoolNameException() throws Exception {
		HttpClientBuilder clientBuilder = Mockito.mock(HttpClientBuilder.class);
		HttpClient mockClient = Mockito.mock(HttpClient.class);
		Mockito.doThrow(new IOException("mock")).when(mockClient).executeOpen(Mockito.any(),Mockito.any(),Mockito.any());
		Mockito.when(clientBuilder.buildClient()).thenReturn(mockClient);
		final RestDataConnector connector = new RestDataConnector(clientBuilder);
		School school = connector.findSchool("123456", "http://localhost/");
		Assert.assertNull(school);
	}

	@Test
	public void testGetSchool_withServer_whenRestReturnsEmptyArray_thenShouldNotReturnSchool() throws Exception {
		final School school = executeWithServer("[]");
		Assert.assertNull(school);
	}

	@Test
	public void testGetSchool_withServer_whenNoMetadata_thenShouldReturnNull() throws Exception {
		final String json = "[\n" + "    {\n" + "        \"koodiUri\":\"oppilaitosnumero_12345\",\n"
				+ "        \"versio\": 1,\n" + "        \"koodiArvo\": \"12345\",\n"
				+ "        \"parentOid\": \"1.2.246.562.10.10000000001\",\n"
				+ "        \"parentName\": \"Mock Education Provider Name\"\n" + "    }\n" + "]";
		final School school = executeWithServer(json);
		Assert.assertNull(school);
	}

	@Test
	public void testGetSchool_withServer_whenEmptyMetadata_thenShouldReturnNull() throws Exception {
		final String json = "[\n" + "    {\n" + "        \"koodiUri\":\"oppilaitosnumero_12345\",\n"
				+ "        \"metadata\": [],\n" + "        \"versio\": 1,\n" + "        \"koodiArvo\": \"12345\",\n"
				+ "        \"parentOid\": \"1.2.246.562.10.10000000001\",\n"
				+ "        \"parentName\": \"Mock Education Provider Name\"\n" + "    }\n" + "]";
		final School school = executeWithServer(json);
		Assert.assertNull(school);
	}

	@Test
	public void testGetSchool_withServer_whenOneLanguageInMetadata_thenShouldReturnSchool() throws Exception {
		final String json = "[\n" + "    {\n" + "        \"koodiUri\":\"oppilaitosnumero_12345\",\n"
				+ "        \"metadata\": [\n" + "            {\n" + "                \"nimi\": \"Mock School Name\",\n"
				+ "                \"lyhytNimi\": \"Mock Short\",\n" + "                \"kieli\": \"FI\"\n"
				+ "            }\n" + "        ],\n" + "        \"versio\": 1,\n"
				+ "        \"koodiArvo\": \"12345\",\n" + "        \"parentOid\": \"1.2.246.562.10.10000000001\",\n"
				+ "        \"parentName\": \"Mock Education Provider Name\"\n" + "    }\n" + "]";
		final School school = executeWithServer(json);
		Assert.assertNotNull(school);
		Assert.assertEquals(school.getName(), expectedSchoolName);
		Assert.assertEquals(school.getId(), expectedSchoolId);
		Assert.assertEquals(school.getParentOid(), expectedParentOid);
		Assert.assertEquals(school.getParentName(), expectedParentName);
	}

	@Test
	public void testGetSchool_withServer_whenOneLanguageInMetadataAndSpaceInSchoolId_thenShouldReturnSchool()
			throws Exception {
		final String json = "[\n" + "    {\n" + "        \"koodiUri\":\"oppilaitosnumero_12345\",\n"
				+ "        \"metadata\": [\n" + "            {\n" + "                \"nimi\": \"Mock School Name\",\n"
				+ "                \"lyhytNimi\": \"Mock Short\",\n" + "                \"kieli\": \"FI\"\n"
				+ "            }\n" + "        ],\n" + "        \"versio\": 1,\n"
				+ "        \"koodiArvo\": \"12345\",\n" + "        \"parentOid\": \"1.2.246.562.10.10000000001\",\n"
				+ "        \"parentName\": \"Mock Education Provider Name\"\n" + "    }\n" + "]";
		final School school = executeWithServer(json, null, " " + expectedSchoolId);
		Assert.assertNotNull(school);
		Assert.assertEquals(school.getName(), expectedSchoolName);
		Assert.assertEquals(school.getId(), expectedSchoolId);
		Assert.assertEquals(school.getParentOid(), expectedParentOid);
		Assert.assertEquals(school.getParentName(), expectedParentName);
	}

	@Test
	public void testGetSchool_withServer_WhenMultipleLanguagesInMetadata_ShouldReturnSchoolWithFIInformation()
			throws Exception {
		final String json = "[\n" + "    {\n" + "        \"koodiUri\":\"oppilaitosnumero_12345\",\n"
				+ "        \"metadata\": [\n" + "            {\n" + "                \"nimi\": \"Mock skolanamn\",\n"
				+ "                \"lyhytNimi\": \"Mock Kort\",\n" + "                \"kieli\": \"SV\"\n"
				+ "            },\n" + "            {\n" + "                \"nimi\": \"Mock koulun nimi\",\n"
				+ "                \"lyhytNimi\": \"Mock Lyhyt\",\n" + "                \"kieli\": \"FI\"\n"
				+ "            },\n" + "            {\n" + "                \"nimi\": \"Mock School Name\",\n"
				+ "                \"lyhytNimi\": \"Mock Short\",\n" + "                \"kieli\": \"EN\"\n"
				+ "            }\n" + "        ],\n" + "        \"versio\": 1,\n"
				+ "        \"koodiArvo\": \"12345\",\n" + "        \"parentOid\": \"1.2.246.562.10.10000000001\",\n"
				+ "        \"parentName\": \"Mock Education Provider Name\"\n" + "    }\n" + "]";
		final School school = executeWithServer(json);
		Assert.assertNotNull(school);
		Assert.assertEquals(school.getName(), "Mock koulun nimi");
		Assert.assertEquals(school.getId(), expectedSchoolId);
		Assert.assertEquals(school.getParentOid(), expectedParentOid);
		Assert.assertEquals(school.getParentName(), expectedParentName);
	}

	@Test
	public void testGetSchool_withServer_MultipleLanguagesInMetadataNoFI_ShouldReturnSchoolWithFirstLanguageInMetadata()
			throws Exception {
		final String json = "[\n" + "    {\n" + "        \"koodiUri\":\"oppilaitosnumero_12345\",\n"
				+ "        \"metadata\": [\n" + "            {\n" + "                \"nimi\": \"Mock skolanamn\",\n"
				+ "                \"lyhytNimi\": \"Mock Kort\",\n" + "                \"kieli\": \"SV\"\n"
				+ "            },\n" + "            {\n" + "                \"nimi\": \"Mock School Name\",\n"
				+ "                \"lyhytNimi\": \"Mock Short\",\n" + "                \"kieli\": \"EN\"\n"
				+ "            }\n" + "        ],\n" + "        \"versio\": 1,\n"
				+ "        \"koodiArvo\": \"12345\",\n" + "        \"parentOid\": \"1.2.246.562.10.10000000001\",\n"
				+ "        \"parentName\": \"Mock Education Provider Name\"\n" + "    }\n" + "]";
		final School school = executeWithServer(json);
		Assert.assertNotNull(school);
		Assert.assertEquals(school.getName(), "Mock skolanamn");
		Assert.assertEquals(school.getId(), expectedSchoolId);
		Assert.assertEquals(school.getParentOid(), expectedParentOid);
		Assert.assertEquals(school.getParentName(), expectedParentName);

	}

	protected School executeWithServer(final String responseContent) throws Exception {
		return executeWithServer(responseContent, null);
	}

	protected School executeWithServer(final String responseContent, final String callerId) throws Exception {
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
			return restDataConnector.findSchool(expectedSchoolId, "http://localhost:" + port + "/mock");
		} catch (Exception e) {
			log.debug("Catched exception", e);
			return null;
		} finally {
			connection.close();
		}
	}

	protected School executeWithServer(final String responseContent, final String callerId, final String schoolId)
			throws Exception {
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
			return restDataConnector.findSchool(schoolId, "http://localhost:" + port + "/mock");
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
