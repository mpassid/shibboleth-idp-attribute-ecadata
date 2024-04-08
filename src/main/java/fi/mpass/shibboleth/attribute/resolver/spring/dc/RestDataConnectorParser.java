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

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.xml.namespace.QName;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

import fi.mpass.shibboleth.attribute.resolver.dc.impl.RestDataConnector;
import net.shibboleth.idp.attribute.resolver.spring.dc.AbstractDataConnectorParser;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import net.shibboleth.utilities.java.support.xml.ElementSupport;

/**
 * A configuration parser for ECA Auth Data API data connector.
 */
public class RestDataConnectorParser extends AbstractDataConnectorParser {

    private final Logger log = LoggerFactory.getLogger(RestDataConnectorParser.class);

    /** Schema name. */
    public static final QName SCHEMA_NAME = new QName(RestDataConnectorNamespaceHandler.NAMESPACE, "RestDataConnector");

    /** Element name for DirectIdpAttributes. */
    public static final QName DIRECT_IDP_ATTRIBUTES_NAME = new QName(RestDataConnectorNamespaceHandler.NAMESPACE, "DirectIdpAttributes");

    /** Element name for Mapping. */
    public static final QName MAPPING_NAME = new QName(RestDataConnectorNamespaceHandler.NAMESPACE, "Mapping");

    /** Element name for SchoolRoleMappins. */
    public static final QName SCHOOL_ROLE_MAPPINGS_NAME = new QName(RestDataConnectorNamespaceHandler.NAMESPACE, "SchoolRoleMappings");

    /** Element name for SchoolRoleCodeMappins. */
    public static final QName SCHOOL_ROLE_CODE_MAPPINGS_NAME = new QName(RestDataConnectorNamespaceHandler.NAMESPACE, "SchoolRoleCodeMappings");
    
    /** Element name for RoleMappins. */
    public static final QName ROLE_MAPPING_NAME = new QName(RestDataConnectorNamespaceHandler.NAMESPACE, "RoleMapping");

    /** Element name for RoleCodeMappins. */
    public static final QName ROLE_CODE_MAPPING_NAME = new QName(RestDataConnectorNamespaceHandler.NAMESPACE, "RoleCodeMapping");
    
    /** {@inheritDoc} */
    @Override
    @Nullable protected Class<RestDataConnector> getBeanClass(@Nonnull final Element element) {
        return RestDataConnector.class;
    }

    /** {@inheritDoc} */
    // Checkstyle: CyclomaticComplexity OFF
    @Override protected void doParse(@Nonnull final Element element, @Nonnull final ParserContext parserContext,
            @Nonnull final BeanDefinitionBuilder builder) {

        super.doParse(element, parserContext, builder);

        String endpointUrl = element.getAttributeNS(null, "endpointUrl");
        
        builder.addPropertyValue("endpointUrl", endpointUrl);
        String hookAttribute = element.getAttributeNS(null, "hookAttribute");
        builder.addPropertyValue("hookAttribute", hookAttribute);
        String idpId = element.getAttributeNS(null, "idpId");
        builder.addPropertyValue("idpId", idpId);
        String resultAttribute = element.getAttributeNS(null, "resultAttributePrefix");
        builder.addPropertyValue("resultAttributePrefix", resultAttribute);
        String token = element.getAttributeNS(null, "token");
        builder.addPropertyValue("token", token);
        String disregardTLSCertificate = element.getAttributeNS(null, "disregardTLSCertificate");
        if (StringSupport.trimOrNull(disregardTLSCertificate) != null) {
            builder.addPropertyValue("disregardTLSCertificate", disregardTLSCertificate);
        } else {
            builder.addPropertyValue("disregardTLSCertificate", "false");
        }
        String nameApiBaseUrl = element.getAttributeNS(null, "nameApiBaseUrl");
        builder.addPropertyValue("nameApiBaseUrl", nameApiBaseUrl);
        String nameApiCallerId = element.getAttributeNS(null, "nameApiCallerId");
        if (StringSupport.trimOrNull(nameApiCallerId) != null) {
            builder.addPropertyValue("nameApiCallerId", nameApiCallerId);
        }
        String allowedSchoolRoles = element.getAttributeNS(null, "allowedSchoolRoles");
        if (StringSupport.trimOrNull(allowedSchoolRoles) != null) {
            builder.addPropertyValue("allowedSchoolRoles", Arrays.asList(allowedSchoolRoles.split(",")));
        }
        String studentRoles = element.getAttributeNS(null, "studentRoles");
        if (StringSupport.trimOrNull(studentRoles) != null) {
            builder.addPropertyValue("studentRoles", Arrays.asList(studentRoles.split(",")));
        }
        String officeTypes = element.getAttributeNS(null, "officeTypes");
        if (StringSupport.trimOrNull(officeTypes) != null) {
            builder.addPropertyValue("officeTypes", Arrays.asList(officeTypes.split(",")));
        }
        final List<Element> directIdpAttributes = ElementSupport.getChildElements(element, DIRECT_IDP_ATTRIBUTES_NAME);
        if (directIdpAttributes != null) {
            final Map<String, Map<String, String>> principalMappings = new HashMap<>();
            final Map<String, Map<String, String>> staticValues = new HashMap<>();
            for (final Element directIdpAttribute : directIdpAttributes) {
                final Map<String, String> valueMappings = new HashMap<>();
                final String idp = directIdpAttribute.getAttributeNS(null, "idpId");
                final String municipality = directIdpAttribute.getAttributeNS(null, "municipality");

                if (municipality != null) {
                    valueMappings.put(RestDataConnector.ATTR_ID_MUNICIPALITIES, municipality);
                }
                final String municipalityCode = directIdpAttribute.getAttributeNS(null, "municipalityCode");
                if (municipalityCode != null) {
                    valueMappings.put(RestDataConnector.ATTR_ID_MUNICIPALITY_CODE, municipalityCode);
                }
                if (!valueMappings.isEmpty()) {
                    staticValues.put(idp, valueMappings);
                }

                final List<Element> mappings = ElementSupport.getChildElements(directIdpAttribute, MAPPING_NAME);
                if (mappings != null) {
                    final Map<String, String> idpMappings = new HashMap<>();
                    for (final Element mapping : mappings) {
                        final String attributeName = mapping.getAttributeNS(null, "attributeName");
                        final String principalName = mapping.getAttributeNS(null, "principalName");
                        idpMappings.put(attributeName, principalName);
                    }
                    principalMappings.put(idp, idpMappings);
                }
            }
            builder.addPropertyValue("principalMappings", principalMappings);            
            builder.addPropertyValue("staticValues", staticValues);            
        }
        final Element schoolRoleCodeMappings = ElementSupport.getFirstChildElement(element, SCHOOL_ROLE_CODE_MAPPINGS_NAME);
        final Map<String,String> roleCodeMap = new HashMap<>();
        if (schoolRoleCodeMappings != null) {
            final List<Element> roleCodeMappings = ElementSupport.getChildElements(schoolRoleCodeMappings, ROLE_CODE_MAPPING_NAME);
            
            for (final Element mapping : roleCodeMappings) {
                final String inputRole = mapping.getAttributeNS(null, "inputRole");
                final String outRole = mapping.getAttributeNS(null, "outputCode");
                roleCodeMap.put(inputRole, outRole);
            }
            builder.addPropertyValue("schoolRoleCodeMappings", roleCodeMap);
        }
        final Element schoolRoleMappings = ElementSupport.getFirstChildElement(element, SCHOOL_ROLE_MAPPINGS_NAME);
        //final List<Element> schoolRoleMappings = ElementSupport.getChildElements(element, SCHOOL_ROLE_MAPPINGS_NAME);
        if (schoolRoleMappings != null) {
            final List<Element> roleMappings = ElementSupport.getChildElements(schoolRoleMappings, ROLE_MAPPING_NAME);
            final Map<String,String> roleMap = new HashMap<>();
            for (final Element mapping : roleMappings) {
                final String inputRole = mapping.getAttributeNS(null, "inputRole");
                final String outRole = mapping.getAttributeNS(null, "outputRole");
                if(roleCodeMap.get(outRole)!=null){
                    roleMap.put(inputRole, outRole);
                } else {
                    log.error("Missing school role code for {}",outRole);
                }
                
            }
            builder.addPropertyValue("schoolRoleMappings", roleMap);
        }
    }
}