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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.auth.Subject;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;

import fi.mpass.shibboleth.attribute.resolver.data.OpintopolkuOppilaitosDTO;
import fi.mpass.shibboleth.attribute.resolver.data.OpintopolkuOppilaitosMetadataDTO;
import fi.mpass.shibboleth.attribute.resolver.data.RolesTypeAdapter;
import fi.mpass.shibboleth.attribute.resolver.data.School;
import fi.mpass.shibboleth.attribute.resolver.data.UserDTO;
import fi.mpass.shibboleth.attribute.resolver.data.UserDTO.AttributesDTO;
import fi.mpass.shibboleth.attribute.resolver.data.UserDTO.RolesDTO;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.resolver.AbstractDataConnector;
import net.shibboleth.idp.attribute.resolver.DataConnector;
import net.shibboleth.idp.attribute.resolver.ResolutionException;
import net.shibboleth.idp.attribute.resolver.ResolvedAttributeDefinition;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolutionContext;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolverWorkContext;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.principal.IdPAttributePrincipal;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.httpclient.HttpClientBuilder;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.StringSupport;

/**
 * This class implements a {@link DataConnector} (resolver plugin) that
 * communicates with ECA user data API for resolving OID using IdP ID and ECA
 * Authn ID.
 *
 * Example configuration (in attribute-resolver.xml):
 *
 * <resolver:DataConnector id="calculateAuthnId" xsi:type=
 * "ecaid:AuthnIdDataConnector" srcAttributeNames="uid" destAttributeName=
 * "authnid"/>
 */
public class RestDataConnector extends AbstractDataConnector {

	/** The attribute id for the username. */
	public static final String ATTR_ID_USERNAME = "username";

	/** The attribute id for the first name. */
	public static final String ATTR_ID_FIRSTNAME = "firstName";

	/** The attribute id for the nick name. */
	public static final String ATTR_ID_NICKNAME = "nickName";

	/** The attribute id for the last name. */
	public static final String ATTR_ID_SURNAME = "surname";

	/** The attribute id for the roles. */
	public static final String ATTR_ID_ROLES = "roles";

	/** The attribute id for the municipalities. */
	public static final String ATTR_ID_MUNICIPALITIES = "municipalities";

	/** The attribute id for the class. */
	public static final String ATTR_ID_CLASSES = "schoolGroups";
	
	/** The attribute id for the groups. */
	public static final String ATTR_ID_GROUPS = "groups";

	/** The attribute id for the group levels. */
	public static final String ATTR_ID_GROUP_LEVELS = "groupLevels";
	
	/** The attribute id for the grade of the user.
	 *  Will replace groupLevels in the future. */
	public static final String ATTR_ID_GRADE = "groupLevel";
	
	public static final String ATTR_ID_LEARNINGMATERIALSCHARGES = "learningMaterialsCharges";
	
	/** The attribute id for the schools. */
	public static final String ATTR_ID_SCHOOLS = "schools";
	
	/** The attribute id for the school codes. */
	public static final String ATTR_ID_SCHOOL_CODES = "schoolCodes";

	/** The attribute id for the school ids. */
	public static final String ATTR_ID_SCHOOL_IDS = "schoolIds";

	/** The attribute id for the school ids. */
	public static final String ATTR_ID_SCHOOL_OIDS = "schoolOids";

	/** The attribute id for the school info. */
	public static final String ATTR_ID_SCHOOL_INFOS = "schoolInfos";
	
	/** The attribute id for the school roles. E.g. Opettaja or Oppilas  */
	public static final String ATTR_ID_SCHOOL_ROLES = "schoolRoles";

	/** The attribute id for the structured roles. */
	public static final String ATTR_ID_STRUCTURED_ROLES = "structuredRoles";

	/** The attribute id for the structured roles with IDs. */
	public static final String ATTR_ID_STRUCTURED_ROLES_WID = "structuredRolesWid";

	/** The attribute id for the structured roles with IDs. */
	public static final String ATTR_ID_STRUCTURED_ROLES_WITH_PARENT_OID = "structuredRolesWithParentOid";

	/** The attribute id prefix for UserDTO/attribute keys. */
	public static final String ATTR_PREFIX = "attr_";

	/**
	 * The attribute id for the national learner id (only used with direct IdP
	 * attributes).
	 */
	public static final String ATTR_ID_LEARNER_ID = "learnerId";

	/**
	 * The attribute id for the legacy ID (only used with direct IdP attributes).
	 */
	public static final String ATTR_ID_LEGACY_ID = "legacyId";

	/**
	 * The attribute id for the municipality code (only used with direct IdP
	 * attributes).
	 */
	public static final String ATTR_ID_MUNICIPALITY_CODE = "municipalityCode";

	public static final String ATTR_ID_EDUCATION_PROVIDER_INFOS = "educationProviderInfos";

	public static final String ATTR_ID_EDUCATION_PROVIDER_OID = "educationProviderOids";

	public static final String ATTR_ID_EDUCATION_PROVIDER_NAME = "educationProviderNames";

	/** The default base URL for fetching school info. */
	public static final String DEFAULT_BASE_URL_SCHOOL_INFO = "https://virkailija.opintopolku.fi/koodisto-service/rest/codeelement/oppilaitosnumero_";

	public static final String HEADER_NAME_CALLER_ID = "caller-id";
	
	private static final String DEFAULT_ATTR_VALUE_SEPARATOR = ";";

	/** Class logging. */
	private final Logger log = LoggerFactory.getLogger(RestDataConnector.class);

	/** The endpoint URL for the REST server. */
	private String endpointUrl;

	/** The attribute used for hooking the user object from the REST server. */
	private String hookAttribute;

	/** The attribute id containing the ECA IdP id. */
	private String idpId;

	/** The attribute id prefix for the resulting attributes. */
	private String resultAttributePrefix;

	/** The token used for authenticating to the REST server. */
	private String token;

	/** The base URL for resolving the school name via API. */
	private String nameApiBaseUrl;

	/** The caller-id used with school information API. */
	private String nameApiCallerId;

	/** The {@link HttpClientBuilder} used for constructing HTTP clients. */
	private HttpClientBuilder httpClientBuilder;
	
	/**
	 * The map used for mapping school roles to the roles used in MPASSid.
	 * The key is the received role and the value is the role which  */
	private Map<String,String> schoolRoleMappings;

	/**
	 * The map used for mapping MPASSid roles to the codes used in MPASSid.
	 * The key is the received role and the value is the code which  */
	private Map<String,String> schoolRoleCodeMappings;
	
	
	/**
	 * The school roles that are allowed in MPASSid-role attributes.
	 */
	private Set<String> allowedSchoolRoles;

	/**
	 * The school roles which are student role.
	 */
	private Set<String> studentRoles;

	/**
	 * The organisation types which are offices.
	 */
	private Set<String> officeTypes;
		
	/**
	 * The map for constructing attributes directly from session {@link Principal}s.
	 * The key is the id and the value contains attribute to principal mappings.
	 */
	private Map<String, Map<String, String>> principalMappings;

	/** The map for static attribute values for an IDP. */
	private Map<String, Map<String, String>> staticValues;

	/**
	 * Constructor.
	 */
	public RestDataConnector() {
		this(null);
	}

	/**
	 * Constructor.
	 * 
	 * @param clientBuilder The {@link HttpClientBuilder} used for constructing HTTP
	 *                      clients.
	 */
	public RestDataConnector(final HttpClientBuilder clientBuilder) {
		super();
		if (clientBuilder == null) {
			httpClientBuilder = new HttpClientBuilder();
		} else {
			httpClientBuilder = clientBuilder;
		}
		principalMappings = Collections.emptyMap();
		staticValues = Collections.emptyMap();
		schoolRoleMappings = Collections.emptyMap();
		schoolRoleCodeMappings = Collections.emptyMap();
		allowedSchoolRoles = Collections.emptySet();
		studentRoles = Collections.emptySet();
		officeTypes = Collections.emptySet();
	}

	/**
	 * Set the map for constructing attributes directly from session
	 * {@link Principal}s. The key is the id and the value contains attribute to
	 * principal mappings.
	 * 
	 * @param mappings What to set.
	 */
	public void setPrincipalMappings(final Map<String, Map<String, String>> mappings) {
		principalMappings = Constraint.isNotNull(mappings, "The map for attributes to principals cannot be null");
	}

	/**
	 * Set the map for static attribute values for an IDP.
	 * 
	 * @param values What to set.
	 */
	public void setStaticValues(final Map<String, Map<String, String>> values) {
		staticValues = Constraint.isNotNull(values, "The map for static values cannot be null");
	}
	
	/**
	 * Set the map for school roles.
	 * 
	 * @param mapping What to set.
	 */
	public void setSchoolRoleMappings(final Map<String,String> mappings) {
		schoolRoleMappings = Constraint.isNotNull(mappings, "The map for school roles cannot be null");
	}
	
	public Map<String,String> getSchoolRoleMappings() {
		return schoolRoleMappings;
	}

	/**
	 * Set the map for role codes.
	 * 
	 * @param mapping What to set.
	 */
	public void setSchoolRoleCodeMappings(final Map<String,String> mappings) {
		schoolRoleCodeMappings = Constraint.isNotNull(mappings, "The map for Mpass roles cannot be null");
	}
	
	public Map<String,String> getSchoolRoleCodeMappings() {
		return schoolRoleCodeMappings;
	}
	
	/**
	 * 
	 */
	public Set<String> getAllowedSchoolRoles() {
		return allowedSchoolRoles;
	}
	
	/**
	 * 
	 */
	public void setAllowedSchoolRoles(final Set<String> roles) {
		allowedSchoolRoles = roles;
	}
	
	/**
	 * 
	 */
	public Set<String> getStudentRoles() {
		return studentRoles;
	}
	
	/**
	 * 
	 */
	public void setStudentRoles(final Set<String> roles) {
		studentRoles = roles;
	}

	/** {@inheritDoc} */
	@Nullable
	@Override
	protected Map<String, IdPAttribute> doDataConnectorResolve(
			@Nonnull final AttributeResolutionContext attributeResolutionContext,
			@Nonnull final AttributeResolverWorkContext attributeResolverWorkContext) throws ResolutionException {
		final Map<String, IdPAttribute> attributes = new HashMap<>();

		final String idpIdValue = collectSingleAttributeValue(
				attributeResolverWorkContext.getResolvedIdPAttributeDefinitions(), idpId);
		if (StringSupport.trimOrNull(idpIdValue) == null) {
			log.error("Could not resolve idpId value");
			throw new ResolutionException("Could not resolve idpId value");
		}

		final UserDTO ecaUser;
		if (principalMappings.keySet().contains(idpIdValue)) {
			log.debug("The direct attribute mapping settings found for IdP {}", idpIdValue);
			ecaUser = getUserDetailsFromIdpAttributes(idpIdValue, attributeResolutionContext);
		} else {
			log.debug("The direct attribute mapping settings were not found for IdP {}", idpIdValue);
			ecaUser = getUserDetailsViaRest(idpIdValue, attributeResolverWorkContext);
		}

		if (ecaUser != null ) {
			if (ecaUser.getAttributes() != null && (ecaUser.getRoles() == null || ecaUser.getRoles().length == 0)) {
				final String schoolIds = ecaUser.getAttribute(ATTR_ID_SCHOOL_CODES) != null
						? ecaUser.getAttribute(ATTR_ID_SCHOOL_CODES).getValue()
						: null;
				final String groups = ecaUser.getAttribute(ATTR_ID_CLASSES) != null
						? ecaUser.getAttribute(ATTR_ID_CLASSES).getValue()
						: null;
				final String schoolRoles = ecaUser.getAttribute(ATTR_ID_SCHOOL_ROLES) != null
						? ecaUser.getAttribute(ATTR_ID_SCHOOL_ROLES).getValue()
						: null;
				final String groupLevel = ecaUser.getAttribute(ATTR_ID_GRADE) != null
						? ecaUser.getAttribute(ATTR_ID_GRADE).getValue()
						: null;
				final String municipality = ecaUser.getAttribute(ATTR_ID_MUNICIPALITIES) != null
						? ecaUser.getAttribute(ATTR_ID_MUNICIPALITIES).getValue()
						: null;
				final String learningMaterialsCharge = ecaUser.getAttribute(ATTR_ID_LEARNINGMATERIALSCHARGES) != null
						? ecaUser.getAttribute(ATTR_ID_LEARNINGMATERIALSCHARGES).getValue()
						: null;

				if (schoolIds != null && schoolRoles != null) {
					log.debug("Trying to set RoleDTOs");
					log.debug("Values: learningMaterialsCharge {}", learningMaterialsCharge);
					ecaUser.setRoles(populateRolesDTOs(schoolIds, groups, schoolRoles, learningMaterialsCharge, groupLevel, municipality));
				} else {
					log.debug("Could not set RolesDTO. Didn't find any schools or roles.");
				}
			}
			populateAttributes(attributes, ecaUser);
		}
		
		return attributes;
	}

	protected UserDTO getUserDetailsFromIdpAttributes(final String idpIdValue,
			@Nonnull final AttributeResolutionContext attributeResolutionContext) {
		
		final UserDTO ecaUser = new UserDTO();

		if (principalMappings.keySet().contains(idpIdValue)) {
			log.debug("The mapping definitions found for idpId {}", idpIdValue);
			final Map<String, String> attributeMappings = principalMappings.get(idpIdValue);

			final AuthenticationContext authnContext = attributeResolutionContext.getParent()
					.getSubcontext(AuthenticationContext.class);
			final Subject subject = authnContext.getAuthenticationResult().getSubject();
			final Set<IdPAttributePrincipal> principals = subject.getPrincipals(IdPAttributePrincipal.class);

			// Try to set municipality and municipality code from direct attributes configuration
			if (staticValues.keySet().contains(idpIdValue)) {
				final String staticMunicipality = staticValues.get(idpIdValue).get(ATTR_ID_MUNICIPALITIES);
				if (staticMunicipality != null) {
					final AttributesDTO municipalityName = ecaUser.new AttributesDTO();
					municipalityName.setName(ATTR_ID_MUNICIPALITIES);
					municipalityName.setValue(staticMunicipality);
					ecaUser.setAttributes(appendNewAttribute(ecaUser.getAttributes(), municipalityName));
				}
				final String staticMunicipalityCode = staticValues.get(idpIdValue).get(ATTR_ID_MUNICIPALITY_CODE);
				if (staticMunicipalityCode != null) {
					final AttributesDTO municipalityCode = ecaUser.new AttributesDTO();
					municipalityCode.setName(ATTR_ID_MUNICIPALITY_CODE);
					municipalityCode.setValue(staticMunicipalityCode);
					ecaUser.setAttributes(appendNewAttribute(ecaUser.getAttributes(), municipalityCode));
				}
			}

			for (final Entry<String, String> entry : attributeMappings.entrySet()) {
				final Iterator<IdPAttributePrincipal> iterator = principals.iterator();
				while (iterator.hasNext()) {					
					final IdPAttributePrincipal principal = iterator.next();
					if (entry.getValue().equals(principal.getName())&&principal.getAttribute()!=null&&principal.getAttribute().getValues().size()>0) {
						switch (entry.getKey()) {
						case ATTR_ID_USERNAME:
							final String mpassUsername = DigestUtils.sha1Hex(idpIdValue + principal.getAttribute().getValues().get(0).getNativeValue().toString());
							ecaUser.setUsername("MPASSOID." + mpassUsername);
							break;
						case ATTR_ID_FIRSTNAME:
							ecaUser.setFirstName(principal.getAttribute().getValues().get(0).getNativeValue().toString());
							break;
						case ATTR_ID_NICKNAME:
							ecaUser.setNickName(principal.getAttribute().getValues().get(0).getNativeValue().toString());
							break;	
						case ATTR_ID_SURNAME:
							ecaUser.setLastName(principal.getAttribute().getValues().get(0).getNativeValue().toString());
							break;
						case ATTR_ID_LEARNER_ID:
							final AttributesDTO learnerId = ecaUser.new AttributesDTO();
							learnerId.setName(ATTR_ID_LEARNER_ID);
							learnerId.setValue(principal.getAttribute().getValues().get(0).getNativeValue().toString());
							ecaUser.setAttributes(appendNewAttribute(ecaUser.getAttributes(), learnerId));
							break;
						case ATTR_ID_LEGACY_ID:
							final AttributesDTO legacyId = ecaUser.new AttributesDTO();
							legacyId.setName(ATTR_ID_LEGACY_ID);
							legacyId.setValue(principal.getAttribute().getValues().get(0).getNativeValue().toString());
							ecaUser.setAttributes(appendNewAttribute(ecaUser.getAttributes(), legacyId));
							break;
						case ATTR_ID_MUNICIPALITY_CODE:
							if (ecaUser.getAttribute(ATTR_ID_MUNICIPALITY_CODE) != null) {
								final AttributesDTO municipalityCode = ecaUser.new AttributesDTO();
								municipalityCode.setName(ATTR_ID_MUNICIPALITY_CODE);
								municipalityCode.setValue(principal.getAttribute().getValues().get(0).getNativeValue().toString());
								ecaUser.setAttributes(appendNewAttribute(ecaUser.getAttributes(), municipalityCode));
							}
							break;
						case ATTR_ID_ROLES:
							final AttributesDTO roles = ecaUser.new AttributesDTO();
							roles.setName(ATTR_ID_SCHOOL_ROLES);
							roles.setValue(principal.getAttribute().getValues().get(0).getNativeValue().toString());
							ecaUser.setAttributes(appendNewAttribute(ecaUser.getAttributes(), roles));
							break;
						case ATTR_ID_GROUPS:
							final AttributesDTO groups = ecaUser.new AttributesDTO();
							groups.setName(ATTR_ID_CLASSES);
							groups.setValue(principal.getAttribute().getValues().get(0).getNativeValue().toString());
							ecaUser.setAttributes(appendNewAttribute(ecaUser.getAttributes(), groups));
							break;
						case ATTR_ID_GROUP_LEVELS:
							final AttributesDTO groupLevel = ecaUser.new AttributesDTO();
							groupLevel.setName(ATTR_ID_GRADE);
							groupLevel.setValue(principal.getAttribute().getValues().get(0).getNativeValue().toString());
							ecaUser.setAttributes(appendNewAttribute(ecaUser.getAttributes(), groupLevel));
							break;
						case ATTR_ID_SCHOOL_IDS:
							final AttributesDTO schoolIds = ecaUser.new AttributesDTO();
							schoolIds.setName(ATTR_ID_SCHOOL_CODES);
							schoolIds.setValue(principal.getAttribute().getValues().get(0).getNativeValue().toString());
							ecaUser.setAttributes(appendNewAttribute(ecaUser.getAttributes(), schoolIds));
							break;
						case ATTR_ID_LEARNINGMATERIALSCHARGES:
							final AttributesDTO learningMaterialCharges = ecaUser.new AttributesDTO();
							learningMaterialCharges.setName(ATTR_ID_LEARNINGMATERIALSCHARGES);
							learningMaterialCharges.setValue(principal.getAttribute().getValues().get(0).getNativeValue().toString());
							ecaUser.setAttributes(appendNewAttribute(ecaUser.getAttributes(), learningMaterialCharges));
							break;
						default:
							break;
						}
						break;
					}						
				}
			}
		} else {
			log.debug("Didn't find requested idpId");
		}
		return ecaUser;
	}
	
	/**
	 * Helper method to split multi-value attribute values with default separator.
	 * 
	 * @param stringToSplit
	 * @return
	 */
	private String[] splitMultivalueAttribute(@Nonnull final String stringToSplit) {
		
		return splitMultivalueAttribute(stringToSplit, DEFAULT_ATTR_VALUE_SEPARATOR);
	}
	
	/**
	 * Helper method to split multi-value attribute values.
	 * 
	 * @param stringToSplit
	 * @param separator
	 * @return	The string array of attribute values.
	 */
	private String[] splitMultivalueAttribute(@Nonnull final String stringToSplit, @Nonnull final String separator) {

		String[] arrStr = null;
		
		if (StringSupport.trimOrNull(stringToSplit) != null)
		{
			arrStr = stringToSplit.split(separator, -1);

			for (int i = 0; i < arrStr.length; i++) {

				arrStr[i] = StringSupport.trimOrNull(arrStr[i].replace("\\", ""));
			}	
		}
		
		return arrStr;
	}
	
	
	/**
	 * Populates RolesDTOs based data received from parameters.
	 * 
	 * @param schoolIds
	 * @param groups
	 * @param schoolRoles
	 * @param learningMaterialsCharges
	 * @param groupLevels
	 * @param municipality
	 * @return
	 */
	protected RolesDTO[] populateRolesDTOs(@Nonnull final String schoolIds, final String groups,
			@Nonnull final String schoolRoles, final String learningMaterialsCharges, final String groupLevels, final String municipality) {

		final String[] arrSchoolIds = Constraint.isNotNull(splitMultivalueAttribute(schoolIds), "SchoolIds cannot be null.");
		final String[] arrGroups = StringSupport.trimOrNull(groups) != null ? splitMultivalueAttribute(groups)
				: new String[0];
		final String[] arrSchoolRoles = Constraint.isNotNull(splitMultivalueAttribute(schoolRoles),
				"SchoolRoles cannot be null.");
		
		String[] arrLearningMaterialsCharge = null;

		if (learningMaterialsCharges != null) {
			arrLearningMaterialsCharge = splitMultivalueAttribute(learningMaterialsCharges);
		}

		log.debug("Populating rolesDTOs.");
		if (arrSchoolIds.length >= 1 && arrSchoolRoles.length >= 1) {

			boolean rulesMatch = false;

			if (arrSchoolIds.length == arrSchoolRoles.length && arrSchoolIds.length == arrGroups.length) {
				rulesMatch = true;
				log.debug("Found matching rule: There is as many school roles and school groups as school ids.");
			} else if ((arrGroups.length <= 1)
					&& (arrSchoolIds.length == arrSchoolRoles.length || arrSchoolRoles.length == 1)) {
				rulesMatch = true;
				log.debug("Found matching rule: No school groups or one school group and as many school id and school roles or one school role.");
			
			} else if (arrGroups.length == arrSchoolIds.length && 
					   arrSchoolRoles.length == 1) {
				rulesMatch = true;
				log.debug("Found matching rule: One school role and as many school groups than school ids.");
			} else {
				log.debug("None of the rules for rolesDTOs did not match.");
			}
			
			if (rulesMatch) {

				final RolesDTO[] rolesDTOs = new RolesDTO[arrSchoolIds.length];

				for (int i = 0; i < arrSchoolIds.length; i++) {
					log.debug("Added schoolId {}", arrSchoolIds[i]);
					final RolesDTO rolesDTO = new UserDTO().new RolesDTO();

					rolesDTO.setSchool(arrSchoolIds[i]);

					if (arrSchoolRoles.length == 1) {
						rolesDTO.setRole(arrSchoolRoles[0]);
						log.debug("Set School Role {}", arrSchoolRoles[0]);
					} else {
						rolesDTO.setRole(arrSchoolRoles[i]);
						log.debug("Set School Role {}", arrSchoolRoles[i]);
					}

					if (StringSupport.trimOrNull(municipality) != null) {
						rolesDTO.setMunicipality(StringSupport.trimOrNull(municipality));
						log.debug("Set municipality {}", municipality);
					}

					if (i == 0 && arrGroups.length == 1) {
						rolesDTO.setGroup(arrGroups[0]);
						log.debug("Set School Group {}", arrGroups[i]);
					} else if (arrGroups.length > 1) {
						rolesDTO.setGroup(arrGroups[i]);
						log.debug("Set School Group {}", arrGroups[i]);
					}

					// Group level is populated only to the first RoleDTO
					if (i == 0 && StringSupport.trimOrNull(groupLevels) != null) {
						try {
							rolesDTO.setGroupLevel(Integer.parseInt(StringSupport.trimOrNull(groupLevels)));
							log.debug("Set School Group Level {}", groupLevels);
						} catch (NumberFormatException e) {
							log.warn("Could not parse given group level {} to an integer", groupLevels);
						}
					}
					
					// Learning Materials Charge attribute
					String roleInSchool = schoolRoleMappings.containsKey(rolesDTO.getRole().toLowerCase()) ? schoolRoleMappings.get(rolesDTO.getRole().toLowerCase()) : rolesDTO.getRole();
					
					if (studentRoles.stream().anyMatch(roleInSchool::equalsIgnoreCase)
							&& arrLearningMaterialsCharge != null) {
						log.trace("Trying to set learningMaterialCharge to RolesDTO. User role {}", roleInSchool);
						int index = -1;

						if (arrLearningMaterialsCharge.length == 1) {
							index = 0;
						} else if (arrLearningMaterialsCharge.length == arrSchoolIds.length) {
							index = i;
						} else {
							log.debug("Count of learningMaterialsCharge attributes ({}) don't match to schoolId attributes ({}).", arrLearningMaterialsCharge.length, arrSchoolIds.length);
						}
												
						try {
							if (index != -1) {
								int value = (Integer.parseInt(StringSupport.trimOrNull(arrLearningMaterialsCharge[index])));
								log.trace("Value of learningMaterialCharge is {}", value);
								if (value == 0 || value == 1) {
									rolesDTO.setLearningMaterialsCharge(value);
									log.trace("LearningMaterialCharge is set to {}", rolesDTO.getLearningMaterialsCharge());
								}
							}
						} catch (NumberFormatException e) {
								log.warn("Could not parse given learning material charge {} to an integer", arrLearningMaterialsCharge[0]);
						}	
					} else {
						log.trace("User role {} didn't match to student roles or didn't receive learningMaterialsCharge attribute. Nothing to do.", roleInSchool);
					}
					
					log.debug("Add role to RoleDTO");
					log.trace("Value of the role is {}", rolesDTO.toString());
					rolesDTOs[i] = rolesDTO;
				}
				
				log.debug("Return RoleDTO");
				return rolesDTOs;
			}
		} else {
			log.debug("Didn't find any schoolIds");
		}
		return null;
	}

	protected AttributesDTO[] appendNewAttribute(final AttributesDTO[] existing, final AttributesDTO newAttr) {
		final AttributesDTO[] newAttrs;
		if (existing == null || existing.length == 0) {
			log.debug("Existing was null, adding new value {}", newAttr.getName());
			newAttrs = new AttributesDTO[1];
			newAttrs[0] = newAttr;
		} else {
			log.debug("Found existing values: {}, adding new {}", existing.length, newAttr.getName());
			newAttrs = new AttributesDTO[existing.length + 1];
			for (int i = 0; i < existing.length; i++) {
				newAttrs[i] = existing[i];
			}
			newAttrs[existing.length] = newAttr;
		}
		return newAttrs;

	}

	protected UserDTO getUserDetailsViaRest(final String idpIdValue,
			@Nonnull final AttributeResolverWorkContext attributeResolverWorkContext) throws ResolutionException {

		log.debug("Calling {} for resolving attributes", endpointUrl);

		String authnIdValue = collectSingleAttributeValue(
				attributeResolverWorkContext.getResolvedIdPAttributeDefinitions(), hookAttribute);
		log.debug("AuthnID before URL encoding = {}", authnIdValue);
		if (authnIdValue == null) {
			log.error("Could not resolve hookAttribute value");
			throw new ResolutionException("Could not resolve hookAttribute value");
		}
		try {
			authnIdValue = URLEncoder.encode(collectSingleAttributeValue(
					attributeResolverWorkContext.getResolvedIdPAttributeDefinitions(), hookAttribute), "UTF-8");
		} catch (UnsupportedEncodingException e) {
			log.error("Could not use UTF-8 for encoding authnID");
			throw new ResolutionException("Could not use UTF-8 for encoding authnID", e);
		}
		log.debug("AuthnID after URL encoding = {}", authnIdValue);
		final String attributeCallUrl = endpointUrl + "?" + idpIdValue + "=" + authnIdValue;

		final HttpClient httpClient;
		try {
			httpClient = buildClient();
		} catch (Exception e) {
			log.error("Could not build HTTP client, skipping attribute resolution", e);
			return null;
		}
		log.debug("Calling URL {}", attributeCallUrl);
		final HttpContext context = HttpClientContext.create();
		final ClassicHttpRequest getMethod = ClassicRequestBuilder.get().setUri(attributeCallUrl)
				.setHeader("Authorization", "Token " + token).build();
		final ClassicHttpResponse restResponse;
		final long timestamp = System.currentTimeMillis();
		try {
			restResponse = httpClient.executeOpen(null,getMethod, context);
		} catch (Exception e) {
			log.error("Could not open connection to REST API, skipping attribute resolution", e);
			return null;
		}

		final int status = restResponse.getCode();
		log.info("API call took {} ms, response code {}", System.currentTimeMillis() - timestamp, status);

		if (log.isTraceEnabled()) {
			if (restResponse.getHeaders() != null) {
				for (Header header : restResponse.getHeaders()) {
					log.trace("Header {}: {}", header.getName(), header.getValue());
				}
			}
		}

		try {
			final String restResponseStr = EntityUtils.toString(restResponse.getEntity(), "UTF-8");
			log.trace("Response {}", restResponseStr);
			if (status == HttpStatus.SC_OK) {
				final Gson gson = new GsonBuilder().registerTypeAdapter(RolesDTO.class, new RolesTypeAdapter())
						.create();
				return gson.fromJson(restResponseStr, UserDTO.class);
			} else {
				log.warn("No attributes found for session with idpId {}, http status {}", idpIdValue, status);
			}
		} catch (Exception e) {
			log.error("Error in connection to Data API", e);
		} finally {
			EntityUtils.consumeQuietly(restResponse.getEntity());
		}
		return null;
	}

	/**
	 * Populates the attributes from the given user object to the given result map.
	 * 
	 * @param attributes The result map of attributes.
	 * @param ecaUser    The source user object.
	 */
	protected void populateAttributes(final Map<String, IdPAttribute> attributes, UserDTO ecaUser) {
		populateAttribute(attributes, ATTR_ID_USERNAME, ecaUser.getUsername());
		populateAttribute(attributes, ATTR_ID_FIRSTNAME, ecaUser.getFirstName());
		populateAttribute(attributes, ATTR_ID_SURNAME, ecaUser.getLastName());
		populateAttribute(attributes, ATTR_ID_NICKNAME, ecaUser.getNickName());
		if (ecaUser.getRoles() != null) {
			log.debug("Roles found: {}", ecaUser.getRoles().length);
			
			for (int i = 0; i < ecaUser.getRoles().length; i++) {
				
				// If allowed school roles are not provided then every role is accepted
				if (ecaUser.getRoles()[i].getRole() == null) {
					continue;
				}
					
				String roleInSchool = schoolRoleMappings.containsKey(ecaUser.getRoles()[i].getRole().toLowerCase()) ? 
						schoolRoleMappings.get(ecaUser.getRoles()[i].getRole().toLowerCase()) : ecaUser.getRoles()[i].getRole();
				
				if (!allowedSchoolRoles.isEmpty() &&
						!allowedSchoolRoles.stream().anyMatch(roleInSchool::equalsIgnoreCase) ) {
					
					log.debug("Provided role {} is not allowed. Moving to next roleDTO.", ecaUser.getRoles()[i].getRole());
					continue;
				}
			
				
				final String rawSchool = ecaUser.getRoles()[i].getSchool();
				final School organization = findSchool(rawSchool, nameApiBaseUrl);
				
				if (organization == null) {
					log.debug("Didn't find any organization.");
					if (isNumeric(rawSchool)) {
						populateAttribute(attributes, ATTR_ID_SCHOOL_IDS, rawSchool);
						populateStructuredRole(attributes, "", rawSchool, ecaUser.getRoles()[i]);
					} else {
						populateAttribute(attributes, ATTR_ID_SCHOOLS, rawSchool);
						populateStructuredRole(attributes, rawSchool, "", ecaUser.getRoles()[i]);
					}
				} else {
					final School school;
					if(officeTypes.contains(organization.getOrganizationType())) {
						school = findSchool(organization.getParentOid(), nameApiBaseUrl);
						if (school == null) {
							log.debug("Didn't find any school.");
							if (isNumeric(rawSchool)) {
								populateAttribute(attributes, ATTR_ID_SCHOOL_IDS, rawSchool);
								populateStructuredRole(attributes, "", rawSchool, ecaUser.getRoles()[i]);
							} else {
								populateAttribute(attributes, ATTR_ID_SCHOOLS, rawSchool);
								populateStructuredRole(attributes, rawSchool, "", ecaUser.getRoles()[i]);
							}
						} else {
							if(organization.getOid()!=null) {
								populateAttribute(attributes, ATTR_ID_SCHOOL_INFOS, organization.getOid() + ";" + organization.getName());
							}
							school.setOfficeName(organization.getName());
							school.setOfficeOid(organization.getOid());
						}
					} else {
						school = organization;
					}
					if(school!=null) {
						log.debug("Found {}",school);
						if(school.getId()!=null){
							populateAttribute(attributes, ATTR_ID_SCHOOL_IDS, school.getId());
							populateAttribute(attributes, ATTR_ID_SCHOOL_INFOS, school.getId() + ";" + school.getName());
						}
						if(school.getOid()!=null){
							populateAttribute(attributes, ATTR_ID_SCHOOL_OIDS, school.getOid());
							populateAttribute(attributes, ATTR_ID_SCHOOL_INFOS, school.getOid() + ";" + school.getName());
						}
						populateAttribute(attributes, ATTR_ID_SCHOOLS, school.getName());
						if(school.getParentOid()!=null){
							populateAttribute(attributes, ATTR_ID_EDUCATION_PROVIDER_OID, school.getParentOid());
							populateAttribute(attributes, ATTR_ID_EDUCATION_PROVIDER_NAME, school.getParentName());
							populateAttribute(attributes, ATTR_ID_EDUCATION_PROVIDER_INFOS,
								school.getParentOid() + ";" + school.getParentName());
						}
						populateStructuredRole(attributes, school.getName(), rawSchool, ecaUser.getRoles()[i]);
						populateStructuredRole(attributes, school, ecaUser.getRoles()[i]);
						
						if (ecaUser.getRoles()[i].getLearningMaterialsCharge() != null) {
							if(school.getId()!=null) {
								populateAttribute(attributes, ATTR_ID_LEARNINGMATERIALSCHARGES, ecaUser.getRoles()[i].getLearningMaterialsCharge().toString() + ";" + school.getId());
							}
							if(school.getOid()!=null) {
								populateAttribute(attributes, ATTR_ID_LEARNINGMATERIALSCHARGES, ecaUser.getRoles()[i].getLearningMaterialsCharge().toString() + ";" + school.getOid());
							}
						}
					}
					
				}
				
				populateAttribute(attributes, ATTR_ID_ROLES, ecaUser.getRoles()[i].getRole());
				populateAttribute(attributes, ATTR_ID_MUNICIPALITIES, ecaUser.getRoles()[i].getMunicipality());
				
				// If multiple group levels or classes are provided only the first ones are populated as attributes
				if (i == 0) {
					populateAttribute(attributes, ATTR_ID_GROUPS, ecaUser.getRoles()[0].getGroup());
					if (ecaUser.getRoles()[0].getGroupLevel() != null) {
						populateAttribute(attributes, ATTR_ID_GROUP_LEVELS,
								ecaUser.getRoles()[0].getGroupLevel().toString());
					}
				}
			}
		}	
		if (ecaUser.getAttributes() != null) {
			for (int i = 0; i < ecaUser.getAttributes().length; i++) {
				final AttributesDTO attribute = ecaUser.getAttributes()[i];
				populateAttribute(attributes, ATTR_PREFIX + attribute.getName(), attribute.getValue());
			}
		}
	}

	/**
	 * Populates an attribute containing a structured role information from the
	 * given object. The value is populated to the given map, or appended to its
	 * values if the attribute already exists.
	 * 
	 * @param attributes The result map of attributes.
	 * @param schoolName The human-readable name of the school.
	 * @param schoolId   The id for the school.
	 * @param role       The role object whose values are added (except school).
	 */
	protected void populateStructuredRole(final Map<String, IdPAttribute> attributes, final String schoolName,
			final String schoolId, final UserDTO.RolesDTO role) {
		
		final String school = schoolName != null ? schoolName : "";
		final String group = role.getGroup() != null ? role.getGroup() : "";
		final String municipality = role.getMunicipality() != null ? role.getMunicipality() : "";
		String aRole;
		
		if (role.getRole() != null) {
			aRole = schoolRoleMappings.containsKey(role.getRole().toLowerCase()) ? schoolRoleMappings.get(role.getRole().toLowerCase()) : role.getRole();
			aRole = aRole.substring(0, 1).toUpperCase() + aRole.substring(1);
		} else {
			aRole = "";
		}
		
		final String structuredRole = municipality + ";" + school + ";" + group + ";" + aRole;
		log.debug("Populating structuredRole: {}", structuredRole);
		populateAttribute(attributes, ATTR_ID_STRUCTURED_ROLES, structuredRole);

		final String structuredRoleWid = municipality + ";" + schoolId + ";" + group + ";" + aRole;
		log.debug("Populating structuredRoleWid: {}", structuredRoleWid);
		if (structuredRoleWid.split(DEFAULT_ATTR_VALUE_SEPARATOR, -1).length == 4) {
			populateAttribute(attributes, ATTR_ID_STRUCTURED_ROLES_WID, structuredRoleWid);
		} else {
			log.debug("StructuredRoleWid has too many components. Value {}", structuredRoleWid);
		}
	}

	/**
	 * Populates an attribute containing a structured role information from the
	 * given object. The value is populated to the given map, or appended to its
	 * values if the attribute already exists.
	 * 
	 * @param attributes The result map of attributes.
	 * @param school     The school object which information is added to role.
	 * @param role       The role object whose values are added (except school).
	 */
	protected void populateStructuredRole(@Nonnull final Map<String, IdPAttribute> attributes,
			@Nonnull final School school, @Nonnull final UserDTO.RolesDTO role) {
		if ((school.getId() != null || school.getOid() != null ) && school.getParentOid() != null) {
			final String group = role.getGroup() != null ? role.getGroup() : "";
			final String schoolId = school.getId() != null ? school.getId() : "";
			final String schoolOid = school.getOid() != null ? school.getOid() : "";
			final String officeOid = school.getOfficeOid() != null ? school.getOfficeOid() : "";

			String roleInSchool;
			
			if (role.getRole() != null) {
				roleInSchool = schoolRoleMappings.containsKey(role.getRole().toLowerCase()) ? schoolRoleMappings.get(role.getRole().toLowerCase()) : role.getRole();
				roleInSchool = roleInSchool.substring(0, 1).toUpperCase() + roleInSchool.substring(1);
			} else {
				roleInSchool = "";
			}

			String codeInSchool;
			if (roleInSchool != "") {
				codeInSchool = schoolRoleCodeMappings.containsKey(roleInSchool) ? schoolRoleCodeMappings.get(roleInSchool) : "-1";
			} else {
				codeInSchool = "";
			}
			
			final String structuredRoleWithParentOid = school.getParentOid() + ";" + schoolId + ";" + group + ";"
					+ roleInSchool+ ";" + codeInSchool + ";" + schoolOid + ";"+ officeOid;
			log.debug("Populating structuredRoleWithParentOid: {}", structuredRoleWithParentOid);
			
			if (structuredRoleWithParentOid.split(DEFAULT_ATTR_VALUE_SEPARATOR, -1).length == 7) {
				populateAttribute(attributes, ATTR_ID_STRUCTURED_ROLES_WITH_PARENT_OID, structuredRoleWithParentOid);
			} else {
				log.debug("structuredRoleWithParentOid has too many components. Value {}", structuredRoleWithParentOid);
			}
		} else {
			log.debug("Could not populate role with education provider oid");
		}
	}

	/**
	 * Populates an attribute with the the given id and value to the given result
	 * map. If the id already exists, the value will be appended to its values.
	 * The same attribute value is appended only ones to the given attribute.
	 * 
	 * @param attributes     The result map of attributes.
	 * @param attributeId    The attribute id.
	 * @param attributeValue The attribute value.
	 */
	protected void populateAttribute(final Map<String, IdPAttribute> attributes, final String attributeId,
			final String attributeValue) {

		String trimmedValue = StringSupport.trimOrNull(attributeValue);

		if (StringSupport.trimOrNull(attributeId) == null || trimmedValue == null) {
			log.debug("Ignoring attirbute {}, null value", attributeId);
			return;
		}

		if (attributes.get(resultAttributePrefix + attributeId) != null) {
			log.trace("Adding a new value to existing attribute {}", resultAttributePrefix + attributeId);
			final IdPAttribute idpAttribute = attributes.get(resultAttributePrefix + attributeId);
			
			final StringAttributeValue attrValue = new StringAttributeValue(trimmedValue);
			if (!idpAttribute.getValues().contains(attrValue)) {				
				log.trace("Existing values {}", idpAttribute.getValues());
				final List<IdPAttributeValue> values = copyExistingValues(idpAttribute.getValues());
				values.add(attrValue);
				idpAttribute.setValues(values);
				log.debug("Added value {} to attribute {}", trimmedValue, resultAttributePrefix + attributeId);
			} else {
				log.debug("Value {} already exists in attribute {}", attrValue, resultAttributePrefix + attributeId);
			}
			
		} else {
			final IdPAttribute idpAttribute = new IdPAttribute(resultAttributePrefix + attributeId);
			final List<IdPAttributeValue> values = new ArrayList<>();
			values.add(new StringAttributeValue(trimmedValue));
			idpAttribute.setValues(values);
			attributes.put(resultAttributePrefix + attributeId, idpAttribute);
			log.debug("Populated {} with value {}", resultAttributePrefix + attributeId, trimmedValue);
		}
	}

	/**
	 * Copies the String values from the source list to a new writable list.
	 * 
	 * @param sourceValues The existing values, expected to be Strings.
	 * @return A writable list containing existing values.
	 */
	@SuppressWarnings("unchecked")
	protected List<IdPAttributeValue> copyExistingValues(final List<IdPAttributeValue> sourceValues) {
		final List<IdPAttributeValue> values = new ArrayList<>();
		final Iterator<IdPAttributeValue> iterator = sourceValues.iterator();
		while (iterator.hasNext()) {
			values.add((IdPAttributeValue) iterator.next());
		}
		return values;
	}

	/**
	 * Sets the endpoint URL for the REST server.
	 * 
	 * @param url The endpointUrl.
	 */
	public void setEndpointUrl(String url) {
		this.endpointUrl = Constraint.isNotEmpty(url, "The endpoint URL cannot be empty!");
	}

	/**
	 * Gets the endpoint URL for the REST server.
	 * 
	 * @return The endpointUrl.
	 */
	public String getEndpointUrl() {
		return this.endpointUrl;
	}

	/**
	 * Sets the attribute used for hooking the user object from the REST server.
	 * 
	 * @param attribute The hookAttribute.
	 */
	public void setHookAttribute(String attribute) {
		this.hookAttribute = Constraint.isNotEmpty(attribute, "The hookAttribute cannot be empty!");
	}

	/**
	 * Gets the attribute used for hooking the user object from the REST server.
	 * 
	 * @return The hookAttribute.
	 */
	public String getHookAttribute() {
		return this.hookAttribute;
	}

	/**
	 * Sets the attribute id containing the ECA IdP id.
	 * 
	 * @param id The idpId.
	 */
	public void setIdpId(String id) {
		this.idpId = Constraint.isNotEmpty(id, "The idpId attribute cannot be empty!");
	}

	/**
	 * Gets the attribute id containing the ECA IdP id.
	 * 
	 * @return The idpId.
	 */
	public String getIdpId() {
		return this.idpId;
	}

	/**
	 * Sets the attribute id prefix for the resulting attributes.
	 * 
	 * @param attributePrefix The resultAttributePrefix.
	 */
	public void setResultAttributePrefix(String attributePrefix) {
		this.resultAttributePrefix = attributePrefix;
	}

	/**
	 * Gets the attribute id prefix for the resulting attributes.
	 * 
	 * @return The resultAttributePrefix.
	 */
	public String getResultAttributePrefix() {
		return this.resultAttributePrefix;
	}

	/**
	 * Sets the token used for authenticating to the REST server.
	 * 
	 * @param authzToken The token.
	 */
	public void setToken(String authzToken) {
		this.token = Constraint.isNotEmpty(authzToken, "The token cannot be empty!");
	}

	/**
	 * Gets the token used for authenticating to the REST server.
	 * 
	 * @return The token.
	 */
	public String getToken() {
		return this.token;
	}

	/**
	 * Sets whether to disregard the TLS certificate protecting the endpoint URL.
	 * 
	 * @param disregard The flag to disregard the certificate.
	 */
	public void setDisregardTLSCertificate(boolean disregard) {
		if (disregard) {
			log.warn("Disregarding TLS certificate in the communication with the REST server!");
		}
		httpClientBuilder.setConnectionDisregardTLSCertificate(disregard);
	}

	/**
	 * Gets whether to disregard the TLS certificate protecting the endpoint URL.
	 * 
	 * @return true if disregarding, false otherwise.
	 */
	public boolean isDisregardTLSCertificate() {
		return httpClientBuilder.isConnectionDisregardTLSCertificate();
	}

	/**
	 * Sets the base URL for resolving the school name via API.
	 * 
	 * @param baseUrl The base URL for resolving the school name via API.
	 */
	public void setNameApiBaseUrl(final String baseUrl) {
		if (StringSupport.trimOrNull(baseUrl) == null) {
			nameApiBaseUrl = DEFAULT_BASE_URL_SCHOOL_INFO;
		} else {
			nameApiBaseUrl = baseUrl;
		}
	}

	/**
	 * Gets the base URL for resolving the school name via API.
	 * 
	 * @return The base URL for resolving the school name via API.
	 */
	public String getNameApiBaseUrl() {
		return nameApiBaseUrl;
	}

	/**
	 * Gets the caller-id used with school information API.
	 * 
	 * @return The caller-id for the school information API.
	 */
	public String getNameApiCallerId() {
		return nameApiCallerId;
	}

	/**
	 * Sets the caller-id used with school information API.
	 * 
	 * @param The caller-id used with school information API.
	 */
	public void setNameApiCallerId(final String callerId) {
		nameApiCallerId = callerId;
	}

	/**
	 * Helper method for collecting single attribute value from the map of attribute
	 * definitions.
	 * 
	 * @param attributeDefinitions The map of {@link ResolvedAttributeDefinition}s.
	 * @param attributeId          The attribute id whose single value is collected.
	 * @return The single value, null if no or multiple values exist.
	 */
	protected String collectSingleAttributeValue(
			@Nonnull final Map<String, ResolvedAttributeDefinition> attributeDefinitions,
			@Nonnull @NotEmpty final String attributeId) {
		final ResolvedAttributeDefinition definition = attributeDefinitions.get(attributeId);
		if (definition == null || definition.getResolvedAttribute() == null) {
			log.warn("Could not find an attribute {} from the context", attributeId);
		} else {
			final List<IdPAttributeValue> values = definition.getResolvedAttribute().getValues();
			if (values.size() == 0) {
				log.warn("No value found for the attribute {}", attributeId);
			} else if (values.size() > 1) {
				log.warn("Multiple values found for the attribute {}, all ignored", attributeId);
			} else {
				log.debug("Found a single value for the attribute {}", attributeId);
				return (String) values.get(0).getNativeValue();
			}
		}
		return null;
	}

	/**
	 * Returns the current {@link HttpClientBuilder}.
	 * 
	 * @return httpClientBuilder.
	 */
	protected HttpClientBuilder getHttpClientBuilder() {
		return httpClientBuilder;
	}

	/**
	 * Builds a {@link HttpClient} using current {@link HttpClientBuilder}.
	 * 
	 * @return The built client.
	 * @throws Exception If the building fails.
	 */
	protected synchronized HttpClient buildClient() throws Exception {
		return getHttpClientBuilder().buildClient();
	}

	/**
	 * Fetch school information from external API.
	 * 
	 * @param clientBuilder The HTTP client builder.
	 * @param schoolId      The school id whose information is fetched.
	 * @param baseUrl       The base URL for the external API. It is appended with
	 *                      the ID of the school.
	 * @return The school object.
	 */
	public School findSchool(final String schoolId, final String baseUrl) {
		final Logger log = LoggerFactory.getLogger(RestDataConnector.class);

		String trimmedSchoolId = StringSupport.trimOrNull(schoolId);
		log.debug("TrimmedSchool: {}", trimmedSchoolId);
		
		if (trimmedSchoolId == null || 
				(isNumeric(trimmedSchoolId) && trimmedSchoolId.length() > 6) ||
				(!isNumeric(trimmedSchoolId) && !trimmedSchoolId.contains("."))) {
			return null;
		}
		final HttpContext context = HttpClientContext.create();
		final ClassicHttpResponse response;
		try {
			final ClassicHttpRequest get = ClassicRequestBuilder.get().setUri(baseUrl + trimmedSchoolId).build();

			if (nameApiCallerId != null) {
				get.setHeader(HEADER_NAME_CALLER_ID, nameApiCallerId);
			}

			response = buildClient().executeOpen(null,get,context);
		} catch (Exception e) {
			log.error("Could not get school information with id {}", schoolId, e);
			return null;
		}
		if (response == null) {
			log.error("Could not get school information with id {}", schoolId);
			return null;
		}
		final String output;
		try {
			output = EntityUtils.toString(response.getEntity(), "UTF-8");
		} catch (ParseException | IOException e) {
			log.error("Could not parse school information response with id {}", schoolId, e);
			return null;
		} finally {
			EntityUtils.consumeQuietly(response.getEntity());
		}
		log.trace("Fetched the following response body: {}", output);
		final Gson gson = new Gson();
		try {
			final OpintopolkuOppilaitosDTO[] oResponse = gson.fromJson(output, OpintopolkuOppilaitosDTO[].class);
			if (oResponse.length == 1 && oResponse[0].getMetadata() != null && oResponse[0].getMetadata().length > 0) {
				log.debug("Successfully fetched information for id {}", trimmedSchoolId);
				log.debug("Fetched data {}",oResponse[0]);
				School school = new School();
				school.setId(oResponse[0].getCodeValue());
				school.setOid(oResponse[0].getOid());
				for (OpintopolkuOppilaitosMetadataDTO metadata : oResponse[0].getMetadata()) {
					if ("FI".equals(metadata.getLanguage())) {
						school.setName(metadata.getName());
					}
				}

				if (null == school.getName()) {
					school.setName(oResponse[0].getMetadata()[0].getName());
				}

				school.setParentOid(oResponse[0].getParentOid());
				school.setParentName(oResponse[0].getParentName());
				school.setOrganizationType(oResponse[0].getOrganizationType());

				return school;
			}
		} catch (JsonSyntaxException | IllegalStateException e) {
			log.warn("Could not parse the response", e);
			log.debug("The unparseable response was {}", output);
		}
		log.warn("Could not find name for id {}", schoolId);
		return null;
	}

	public static String getAttrIdUsername() {
		return ATTR_ID_USERNAME;
	}

	public static String getAttrIdFirstname() {
		return ATTR_ID_FIRSTNAME;
	}

	public static String getAttrIdNickname() {
		return ATTR_ID_NICKNAME;
	}

	public static String getAttrIdSurname() {
		return ATTR_ID_SURNAME;
	}

	public static String getAttrIdRoles() {
		return ATTR_ID_ROLES;
	}

	public static String getAttrIdMunicipalities() {
		return ATTR_ID_MUNICIPALITIES;
	}

	public static String getAttrIdClasses() {
		return ATTR_ID_CLASSES;
	}

	public static String getAttrIdGroups() {
		return ATTR_ID_GROUPS;
	}

	public static String getAttrIdGroupLevels() {
		return ATTR_ID_GROUP_LEVELS;
	}

	public static String getAttrIdGrade() {
		return ATTR_ID_GRADE;
	}

	public static String getAttrIdLearningmaterialscharges() {
		return ATTR_ID_LEARNINGMATERIALSCHARGES;
	}

	public static String getAttrIdSchools() {
		return ATTR_ID_SCHOOLS;
	}

	public static String getAttrIdSchoolCodes() {
		return ATTR_ID_SCHOOL_CODES;
	}

	public static String getAttrIdSchoolIds() {
		return ATTR_ID_SCHOOL_IDS;
	}

	public static String getAttrIdSchoolOids() {
		return ATTR_ID_SCHOOL_OIDS;
	}

	public static String getAttrIdSchoolInfos() {
		return ATTR_ID_SCHOOL_INFOS;
	}

	public static String getAttrIdSchoolRoles() {
		return ATTR_ID_SCHOOL_ROLES;
	}

	public static String getAttrIdStructuredRoles() {
		return ATTR_ID_STRUCTURED_ROLES;
	}

	public static String getAttrIdStructuredRolesWid() {
		return ATTR_ID_STRUCTURED_ROLES_WID;
	}

	public static String getAttrIdStructuredRolesWithParentOid() {
		return ATTR_ID_STRUCTURED_ROLES_WITH_PARENT_OID;
	}

	public static String getAttrPrefix() {
		return ATTR_PREFIX;
	}

	public static String getAttrIdLearnerId() {
		return ATTR_ID_LEARNER_ID;
	}

	public static String getAttrIdLegacyId() {
		return ATTR_ID_LEGACY_ID;
	}

	public static String getAttrIdMunicipalityCode() {
		return ATTR_ID_MUNICIPALITY_CODE;
	}

	public static String getAttrIdEducationProviderInfos() {
		return ATTR_ID_EDUCATION_PROVIDER_INFOS;
	}

	public static String getAttrIdEducationProviderOid() {
		return ATTR_ID_EDUCATION_PROVIDER_OID;
	}

	public static String getAttrIdEducationProviderName() {
		return ATTR_ID_EDUCATION_PROVIDER_NAME;
	}

	public static String getDefaultBaseUrlSchoolInfo() {
		return DEFAULT_BASE_URL_SCHOOL_INFO;
	}

	public static String getHeaderNameCallerId() {
		return HEADER_NAME_CALLER_ID;
	}

	public static String getDefaultAttrValueSeparator() {
		return DEFAULT_ATTR_VALUE_SEPARATOR;
	}

	public Logger getLog() {
		return log;
	}

	public void setHttpClientBuilder(HttpClientBuilder httpClientBuilder) {
		this.httpClientBuilder = httpClientBuilder;
	}

	public Set<String> getOfficeTypes() {
		return officeTypes;
	}

	public void setOfficeTypes(Set<String> officeTypes) {
		this.officeTypes = officeTypes;
	}

	public Map<String, Map<String, String>> getPrincipalMappings() {
		return principalMappings;
	}

	public Map<String, Map<String, String>> getStaticValues() {
		return staticValues;
	}

	private boolean isNumeric(String value) {		
		try {
			Integer.parseInt(value);
			return true;
		} catch (Exception e) {
			return false;
		}		
	}
}
