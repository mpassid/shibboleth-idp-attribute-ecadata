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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.auth.Subject;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.ParseException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

import fi.mpass.shibboleth.attribute.resolver.data.OpintopolkuOppilaitosDTO;
import fi.mpass.shibboleth.attribute.resolver.data.UserDTO;
import fi.mpass.shibboleth.attribute.resolver.data.UserDTO.AttributesDTO;
import fi.mpass.shibboleth.attribute.resolver.data.UserDTO.RolesDTO;
import fi.mpass.shibboleth.authn.principal.impl.KeyValuePrincipal;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.resolver.AbstractDataConnector;
import net.shibboleth.idp.attribute.resolver.ResolutionException;
import net.shibboleth.idp.attribute.resolver.ResolvedAttributeDefinition;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolutionContext;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolverWorkContext;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

/**
 * This class implements a {@link DataConnector} (resolver plugin) that communicates with ECA user data API
 * for resolving OID using IdP ID and ECA Authn ID.
 *
 * Example configuration (in attribute-resolver.xml):
 *
 * <resolver:DataConnector id="calculateAuthnId" xsi:type="ecaid:AuthnIdDataConnector" srcAttributeNames="uid"
 * destAttributeName="authnid"/> 
 */
public class RestDataConnector extends AbstractDataConnector {
    
    /** The attribute id for the username. */
    public static final String ATTR_ID_USERNAME = "username";
    
    /** The attribute id for the first name. */
    public static final String ATTR_ID_FIRSTNAME = "firstName";
    
    /** The attribute id for the last name. */
    public static final String ATTR_ID_SURNAME = "surname";
    
    /** The attribute id for the roles. */
    public static final String ATTR_ID_ROLES = "roles";
    
    /** The attribute id for the municipalities. */
    public static final String ATTR_ID_MUNICIPALITIES = "municipalities";
    
    /** The attribute id for the groups. */
    public static final String ATTR_ID_GROUPS = "groups";
    
    /** The attribute id for the schools. */
    public static final String ATTR_ID_SCHOOLS = "schools";

    /** The attribute id for the school ids. */
    public static final String ATTR_ID_SCHOOL_IDS = "schoolIds";

    /** The attribute id for the structured roles. */
    public static final String ATTR_ID_STRUCTURED_ROLES = "structuredRoles";

    /** The attribute id for the structured roles with IDs. */
    public static final String ATTR_ID_STRUCTURED_ROLES_WID = "structuredRolesWid";

    /** The attribute id prefix for UserDTO/attribute keys. */
    public static final String ATTR_PREFIX = "attr_";
    
    /** The attribute id for the legacy ID (only used with direct IdP attributes). */
    public static final String ATTR_ID_LEGACY_ID = "legacyId";
    
    /** The attribute id for the municipality code (only used with direct IdP attributes). */
    public static final String ATTR_ID_MUNICIPALITY_CODE = "municipalityCode";
    
    /** The default base URL for fetching school info. */
    public static final String DEFAULT_BASE_URL_SCHOOL_INFO = 
            "https://virkailija.opintopolku.fi/koodisto-service/rest/codeelement/oppilaitosnumero_";

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

    /** The {@link HttpClientBuilder} used for constructing HTTP clients. */
    private HttpClientBuilder httpClientBuilder;
    
    /**
     * The map for constructing attributes directly from session {@link Principal}s. The key is the 
     * id and the value contains attribute to principal mappings.
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
     * @param clientBuilder The {@link HttpClientBuilder} used for constructing HTTP clients.
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
    }
    
    /**
     * Set the map for constructing attributes directly from session {@link Principal}s. The key is the 
     * id and the value contains attribute to principal mappings.
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

    /** {@inheritDoc} */
    @Nullable @Override protected Map<String, IdPAttribute> doDataConnectorResolve(
            @Nonnull final AttributeResolutionContext attributeResolutionContext,
            @Nonnull final AttributeResolverWorkContext attributeResolverWorkContext) throws ResolutionException {
        final Map<String, IdPAttribute> attributes = new HashMap<>();
        
        final String idpIdValue =
                collectSingleAttributeValue(attributeResolverWorkContext.getResolvedIdPAttributeDefinitions(), idpId);
        if (StringSupport.trimOrNull(idpIdValue) == null) {
            log.error("Could not resolve idpId value");
            throw new ResolutionException("Could not resolve idpId value");
        }

        final UserDTO ecaUser;
        if (principalMappings.keySet().contains(idpIdValue)) {
            log.debug("The direct attribute mapping settings found for IdP {}", idpIdValue);
            ecaUser = getUserDetailsFromAttributes(idpIdValue, attributeResolutionContext);
        } else {
            log.debug("The direct attribute mapping settings were not found for IdP {}", idpIdValue);
            ecaUser = getUserDetailsViaRest(idpIdValue, attributeResolverWorkContext);
        }
        
        if (ecaUser != null) {
            populateAttributes(attributes, ecaUser);
            log.debug("{} attributes are now populated", attributes.size());
        } else {
            log.warn("Could not populate the attributes");
        }
        
        return attributes;
    }
    
    protected UserDTO getUserDetailsFromAttributes(final String idpIdValue, @Nonnull final AttributeResolutionContext attributeResolutionContext) {
        final UserDTO ecaUser = new UserDTO();
        
        if (principalMappings.keySet().contains(idpIdValue)) {
            log.debug("The mapping definitions found for idpId {}", idpIdValue);
            final Map<String, String> attributeMappings = principalMappings.get(idpIdValue);
            
            final AuthenticationContext authnContext = attributeResolutionContext.getParent().getSubcontext(AuthenticationContext.class);
            final Subject subject = authnContext.getAuthenticationResult().getSubject();
            final Set<KeyValuePrincipal> principals = subject.getPrincipals(KeyValuePrincipal.class);
            
            final Set<String> roles = new HashSet<>();
            final Set<String> groups = new HashSet<>();
            final Set<String> schoolIds = new HashSet<>();
                        
            for (final Entry<String, String> entry : attributeMappings.entrySet()) {
                final Iterator<KeyValuePrincipal> iterator = principals.iterator();
                while (iterator.hasNext()) {
                    final KeyValuePrincipal principal = iterator.next();
                    if (entry.getValue().equals(principal.getKey())) {
                        switch (entry.getKey()) {
                            case ATTR_ID_USERNAME:
                                //TODO: generated in the same was as in the data component
                                final String mpassUsername = DigestUtils.sha1Hex(idpIdValue + principal.getValue());
                                ecaUser.setUsername("MPASSOID." + mpassUsername);
                                break;
                            case ATTR_ID_FIRSTNAME:
                                ecaUser.setFirstName(principal.getValue());
                                break;
                            case ATTR_ID_SURNAME:
                                ecaUser.setLastName(principal.getValue());
                                break;
                            case ATTR_ID_LEGACY_ID:
                                final AttributesDTO legacyId = ecaUser.new AttributesDTO();
                                legacyId.setName(ATTR_ID_LEGACY_ID);
                                legacyId.setValue(principal.getValue());
                                ecaUser.setAttributes(appendNewAttribute(ecaUser.getAttributes(), legacyId));
                                break;
                            case ATTR_ID_MUNICIPALITY_CODE:
                                final AttributesDTO municipalityCode = ecaUser.new AttributesDTO();
                                municipalityCode.setName(ATTR_ID_MUNICIPALITY_CODE);
                                municipalityCode.setValue(principal.getValue());
                                ecaUser.setAttributes(appendNewAttribute(ecaUser.getAttributes(), municipalityCode));
                                break;
                            case ATTR_ID_ROLES:
                                roles.add(principal.getValue());
                                break;
                            case ATTR_ID_GROUPS:
                                groups.add(principal.getValue());
                                break;
                            case ATTR_ID_SCHOOL_IDS:
                                String value = principal.getValue();
                                if (value != null && value.contains(";")) {
                                    String[] codes = value.split(";");
                                    for (String code : codes) {
                                        schoolIds.add(code.replace("\\", ""));
                                    }
                                } else {
                                    schoolIds.add(principal.getValue());
                                }
                                break;
                            default:
                                break;
                        }
                        break;
                    }
                }
            }
            
            if (roles.size() != 1) {
                log.warn("Could not find a single role, the size of the set is {}", roles.size());
            } else {
                final RolesDTO[] rolesDTOs = new RolesDTO[schoolIds.size()];
                int i = 0;
                for (final String schoolId : schoolIds) {
                    log.debug("Added schoolId {}", schoolId);
                    final RolesDTO rolesDTO = ecaUser.new RolesDTO();
                    rolesDTO.setSchool(schoolId);
                    rolesDTO.setRole(roles.iterator().next());
                    //TODO: only one group currently supported
                    if (staticValues.keySet().contains(idpIdValue)) {
                        final String municipality = staticValues.get(idpIdValue).get(ATTR_ID_MUNICIPALITIES);
                        if (StringSupport.trimOrNull(municipality) != null) {
                            rolesDTO.setMunicipality(municipality);
                        }
                        final String munCode = staticValues.get(idpIdValue).get(ATTR_ID_MUNICIPALITY_CODE);
                        if (StringSupport.trimOrNull(munCode) != null) {
                            final AttributesDTO municipalityCode = ecaUser.new AttributesDTO();
                            municipalityCode.setName(ATTR_ID_MUNICIPALITY_CODE);
                            municipalityCode.setValue(munCode);
                            ecaUser.setAttributes(appendNewAttribute(ecaUser.getAttributes(), municipalityCode));
                        }
                    }
                    if (!groups.isEmpty()) {
                        rolesDTO.setGroup(groups.iterator().next());
                    }
                    rolesDTOs[i] = rolesDTO;
                    i = i + 1;
                }
                ecaUser.setRoles(rolesDTOs);
            }
            
        }
        return ecaUser;
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
    
    protected UserDTO getUserDetailsViaRest(final String idpIdValue, @Nonnull final AttributeResolverWorkContext attributeResolverWorkContext) throws ResolutionException {

        
        log.debug("Calling {} for resolving attributes", endpointUrl);

        String authnIdValue = collectSingleAttributeValue(attributeResolverWorkContext.
                getResolvedIdPAttributeDefinitions(), hookAttribute);
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
        final HttpUriRequest getMethod = RequestBuilder.get().setUri(attributeCallUrl)
                .setHeader("Authorization", "Token " + token).build();
        final HttpResponse restResponse;
        final long timestamp = System.currentTimeMillis();
        try {
            restResponse = httpClient.execute(getMethod, context);
        } catch (Exception e) {
            log.error("Could not open connection to REST API, skipping attribute resolution", e);
            return null;
        }

        final int status = restResponse.getStatusLine().getStatusCode();
        log.info("API call took {} ms, response code {}", System.currentTimeMillis() - timestamp, status);
        
        if (log.isTraceEnabled()) {
            if (restResponse.getAllHeaders() != null) {
                for (Header header : restResponse.getAllHeaders()) {
                    log.trace("Header {}: {}", header.getName(), header.getValue());
                }
            }
        }

        try {
            final String restResponseStr = EntityUtils.toString(restResponse.getEntity(), "UTF-8");
            log.trace("Response {}", restResponseStr);
            if (status == HttpStatus.SC_OK) {
                final Gson gson = new Gson();
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
     * @param ecaUser The source user object.
     */
    protected void populateAttributes(final Map<String, IdPAttribute> attributes, UserDTO ecaUser) {
        populateAttribute(attributes, ATTR_ID_USERNAME, ecaUser.getUsername());
        populateAttribute(attributes, ATTR_ID_FIRSTNAME, ecaUser.getFirstName());
        populateAttribute(attributes, ATTR_ID_SURNAME, ecaUser.getLastName());
        if (ecaUser.getRoles() != null) {
            for (int i = 0; i < ecaUser.getRoles().length; i++) {
                final String rawSchool = ecaUser.getRoles()[i].getSchool();
                final String mappedSchool = getSchoolName(getHttpClientBuilder(), rawSchool, nameApiBaseUrl);
                if (mappedSchool == null) {
                    if (StringUtils.isNumeric(rawSchool)) {
                        populateAttribute(attributes, ATTR_ID_SCHOOL_IDS, rawSchool);                        
                        populateStructuredRole(attributes, "", rawSchool, ecaUser.getRoles()[i]);
                    } else {                        
                        populateAttribute(attributes, ATTR_ID_SCHOOLS, rawSchool);                    
                        populateStructuredRole(attributes, rawSchool, "", ecaUser.getRoles()[i]);
                    }
                } else {
                    populateAttribute(attributes, ATTR_ID_SCHOOLS, mappedSchool);
                    populateAttribute(attributes, ATTR_ID_SCHOOL_IDS, rawSchool);
                    populateStructuredRole(attributes, mappedSchool, rawSchool, ecaUser.getRoles()[i]);
                }
                populateAttribute(attributes, ATTR_ID_GROUPS, ecaUser.getRoles()[i].getGroup());
                populateAttribute(attributes, ATTR_ID_ROLES, ecaUser.getRoles()[i].getRole());
                populateAttribute(attributes, ATTR_ID_MUNICIPALITIES, ecaUser.getRoles()[i].getMunicipality());
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
     * Populates an attribute containing a structured role information from the given object. The value is
     * populated to the given map, or appended to its values if the attribute already exists.
     * 
     * @param attributes The result map of attributes.
     * @param schoolName The human-readable name of the school.
     * @param schoolId The id for the school.
     * @param role The role object whose values are added (except school).
     */
    protected void populateStructuredRole(final Map<String, IdPAttribute> attributes, final String schoolName, 
            final String schoolId, final UserDTO.RolesDTO role) {
        final String school = schoolName != null ? schoolName : "";
        final String group = role.getGroup() != null ? role.getGroup() : "";
        final String aRole = role.getRole() != null ? role.getRole() : "";
        final String municipality = role.getMunicipality() != null ? role.getMunicipality() : "";
        final String structuredRole = municipality + ";" + school + ";" + group + ";" + aRole;
        populateAttribute(attributes, ATTR_ID_STRUCTURED_ROLES, structuredRole);
        final String structuredRoleWid = municipality + ";" + schoolId + ";" + group + ";" + aRole;
        populateAttribute(attributes, ATTR_ID_STRUCTURED_ROLES_WID, structuredRoleWid);
    }
    
    /**
     * Populates an attribute with the the given id and value to the given result map. If the id already
     * exists, the value will be appended to its values.
     * 
     * @param attributes The result map of attributes.
     * @param attributeId The attribute id.
     * @param attributeValue The attribute value.
     */
    protected void populateAttribute(final Map<String, IdPAttribute> attributes, 
            final String attributeId, final String attributeValue) {
        if (StringSupport.trimOrNull(attributeId) == null || StringSupport.trimOrNull(attributeValue) == null) {
            log.debug("Ignoring attirbute {}, null value", attributeId);
            return;
        }
        if (attributes.get(resultAttributePrefix + attributeId) != null) {
            log.trace("Adding a new value to existing attribute {}", resultAttributePrefix + attributeId);
            final IdPAttribute idpAttribute = attributes.get(resultAttributePrefix + attributeId);
            log.trace("Existing values {}", idpAttribute.getValues());
            final List<IdPAttributeValue<String>> values = copyExistingValues(idpAttribute.getValues());
            values.add(new StringAttributeValue(attributeValue));
            idpAttribute.setValues(values);
            log.debug("Added value {} to attribute {}", attributeValue, resultAttributePrefix + attributeId);
        } else {
            final IdPAttribute idpAttribute = new IdPAttribute(resultAttributePrefix + attributeId);
            final List<IdPAttributeValue<String>> values = new ArrayList<>();
            values.add(new StringAttributeValue(attributeValue));
            idpAttribute.setValues(values);
            attributes.put(resultAttributePrefix + attributeId, idpAttribute);
            log.debug("Populated {} with value {}", resultAttributePrefix + attributeId, attributeValue);
        }
    }
    
    /**
     * Copies the String values from the source list to a new writable list.
     * @param sourceValues The existing values, expected to be Strings.
     * @return A writable list containing existing values.
     */
    @SuppressWarnings("unchecked")
    protected List<IdPAttributeValue<String>> copyExistingValues(final List<IdPAttributeValue<?>> sourceValues) {
        final List<IdPAttributeValue<String>> values = new ArrayList<>();
        final Iterator<IdPAttributeValue<?>> iterator = sourceValues.iterator();
        while (iterator.hasNext()) {
            values.add((IdPAttributeValue<String>)iterator.next());
        }
        return values;
    }

    /**
     * Sets the endpoint URL for the REST server.
     * @param url The endpointUrl.
     */
    public void setEndpointUrl(String url) {
        this.endpointUrl = Constraint.isNotEmpty(url, "The endpoint URL cannot be empty!");
    }
    
    /**
     * Gets the endpoint URL for the REST server.
     * @return The endpointUrl.
     */
    public String getEndpointUrl() {
        return this.endpointUrl;
    }

    /**
     * Sets the attribute used for hooking the user object from the REST server.
     * @param attribute The hookAttribute.
     */
    public void setHookAttribute(String attribute) {
        this.hookAttribute = Constraint.isNotEmpty(attribute, "The hookAttribute cannot be empty!");
    }
    
    /**
     * Gets the attribute used for hooking the user object from the REST server.
     * @return The hookAttribute.
     */
    public String getHookAttribute() {
        return this.hookAttribute;
    }

    /**
     * Sets the attribute id containing the ECA IdP id.
     * @param id The idpId.
     */
    public void setIdpId(String id) {
        this.idpId = Constraint.isNotEmpty(id, "The idpId attribute cannot be empty!");
    }
    
    
    /**
     * Gets the attribute id containing the ECA IdP id.
     * @return The idpId.
     */
    public String getIdpId() {
        return this.idpId;
    }

    /**
     * Sets the attribute id prefix for the resulting attributes. 
     * @param attributePrefix The resultAttributePrefix.
     */
    public void setResultAttributePrefix(String attributePrefix) {
        this.resultAttributePrefix = attributePrefix;
    }
    
    /**
     * Gets the attribute id prefix for the resulting attributes.
     * @return The resultAttributePrefix.
     */
    public String getResultAttributePrefix() {
        return this.resultAttributePrefix;
    }

    /**
     * Sets the token used for authenticating to the REST server.
     * @param authzToken The token.
     */
    public void setToken(String authzToken) {
        this.token = Constraint.isNotEmpty(authzToken, "The token cannot be empty!");
    }
    
    /**
     * Gets the token used for authenticating to the REST server.
     * @return The token.
     */
    public String getToken() {
        return this.token;
    }

    /**
     * Sets whether to disregard the TLS certificate protecting the endpoint URL.
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
     * @return true if disregarding, false otherwise.
     */
    public boolean isDisregardTLSCertificate() {
        return httpClientBuilder.isConnectionDisregardTLSCertificate();
    }
    
    /**
     * Sets the base URL for resolving the school name via API.
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
     * @return The base URL for resolving the school name via API.
     */
    public String getNameApiBaseUrl() {
        return nameApiBaseUrl;
    }

    /**
     * Helper method for collecting single attribute value from the map of attribute definitions.
     * @param attributeDefinitions The map of {@link ResolvedAttributeDefinition}s.
     * @param attributeId The attribute id whose single value is collected.
     * @return The single value, null if no or multiple values exist.
     */
    protected String collectSingleAttributeValue(
            @Nonnull final Map<String, ResolvedAttributeDefinition> attributeDefinitions,
            @Nonnull @NotEmpty final String attributeId) {
        final ResolvedAttributeDefinition definition = attributeDefinitions.get(attributeId);
        if (definition == null || definition.getResolvedAttribute() == null) {
            log.warn("Could not find an attribute {} from the context", attributeId);
        } else {
            final List<IdPAttributeValue<?>> values = definition.getResolvedAttribute().getValues();
            if (values.size() == 0) {
                log.warn("No value found for the attribute {}", attributeId);
            } else if (values.size() > 1) {
                log.warn("Multiple values found for the attribute {}, all ignored", attributeId);
            } else {
                log.debug("Found a single value for the attribute {}", attributeId);
                return (String) values.get(0).getValue();
            }
        }
        return null;
    }
    
    /**
     * Returns the current {@link HttpClientBuilder}.
     * @return httpClientBuilder.
     */
    protected HttpClientBuilder getHttpClientBuilder() {
        return httpClientBuilder;
    }
    
    /**
     * Builds a {@link HttpClient} using current {@link HttpClientBuilder}.
     * @return The built client.
     * @throws Exception If the building fails.
     */
    protected synchronized HttpClient buildClient() throws Exception {
        return getHttpClientBuilder().buildClient();
    }
    
    /**
     * Fetch school name from external API.
     * @param clientBuilder The HTTP client builder.
     * @param id The school id whose information is fetched.
     * @param baseUrl The base URL for the external API. It is appended with the ID of the school.
     * @return The name of the school.
     */
    public static synchronized String getSchoolName(final HttpClientBuilder clientBuilder, 
            final String id, final String baseUrl) {
        final Logger log = LoggerFactory.getLogger(RestDataConnector.class);
        if (StringSupport.trimOrNull(id) == null || !StringUtils.isNumeric(id) || id.length() > 6) {
            return null;
        }
        final HttpResponse response;
        try {
            final HttpUriRequest get = RequestBuilder.get().setUri(baseUrl + id).build();
            response = clientBuilder.buildClient().execute(get);
        } catch (Exception e) {
            log.error("Could not get school information with id {}", id, e);
            return null;
        }
        if (response == null) {
            log.error("Could not get school information with id {}", id);
            return null;
        }
        final String output;
        try {
            output = EntityUtils.toString(response.getEntity(), "UTF-8");
        } catch (ParseException | IOException e) {
            log.error("Could not parse school information response with id {}", id, e);
            return null;
        } finally {
            EntityUtils.consumeQuietly(response.getEntity());
        }
        log.trace("Fetched the following response body: {}", output);
        final Gson gson = new Gson();
        try {
            final OpintopolkuOppilaitosDTO[] oResponse = gson.fromJson(output, OpintopolkuOppilaitosDTO[].class);
            if (oResponse.length == 1 && oResponse[0].getMetadata() != null && oResponse[0].getMetadata().length == 1) {
                log.debug("Successfully fetched name for id {}", id);
                return oResponse[0].getMetadata()[0].getName();
            }
        } catch (JsonSyntaxException | IllegalStateException e) {
            log.warn("Could not parse the response", e);
            log.debug("The unparseable response was {}", output);
        }
        log.warn("Could not find name for id {}", id);
        return null;
    }
}
