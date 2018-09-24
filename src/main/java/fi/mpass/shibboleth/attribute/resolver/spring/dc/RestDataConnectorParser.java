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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;

import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

import fi.mpass.shibboleth.attribute.resolver.dc.impl.RestDataConnector;
import net.shibboleth.idp.attribute.resolver.spring.dc.impl.AbstractDataConnectorParser;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import net.shibboleth.utilities.java.support.xml.ElementSupport;

/**
 * A configuration parser for ECA Auth Data API data connector.
 */
public class RestDataConnectorParser extends AbstractDataConnectorParser {

    /** Schema name. */
    public static final QName SCHEMA_NAME = new QName(RestDataConnectorNamespaceHandler.NAMESPACE, "RestDataConnector");

    /** Element name for DirectIdpAttributes. */
    public static final QName DIRECT_IDP_ATTRIBUTES_NAME = new QName(RestDataConnectorNamespaceHandler.NAMESPACE, "DirectIdpAttributes");

    /** Element name for Mapping. */
    public static final QName MAPPING_NAME = new QName(RestDataConnectorNamespaceHandler.NAMESPACE, "Mapping");

    
    /** {@inheritDoc} */
    protected Class<RestDataConnector> getNativeBeanClass() {
        return RestDataConnector.class;
    }

    /** {@inheritDoc} */
    protected void doV2Parse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
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
        final List<Element> directIdpAttributes = ElementSupport.getChildElements(element, DIRECT_IDP_ATTRIBUTES_NAME);
        if (directIdpAttributes != null) {
            final Map<String, Map<String, String>> principalMappings = new HashMap<>();
            for (final Element directIdpAttribute : directIdpAttributes) {
                final String idp = directIdpAttribute.getAttributeNS(null, "idpId");
                final List<Element> mappings = ElementSupport.getChildElements(directIdpAttribute, MAPPING_NAME);
                if (mappings != null) {
                    final Map<String, String> idpMappings = new HashMap<>();
                    for (final Element mapping : mappings) {
                        final String attributeName = mapping.getAttributeNS(null, "attributeName");
                        final String principalName = mapping.getAttributeNS(null, "principalName");
                        idpMappings.put(attributeName, principalName);
                    }
                    final String municipality = directIdpAttribute.getAttributeNS(null, "municipality");
                    if (municipality != null) {
                        idpMappings.put(RestDataConnector.ATTR_ID_MUNICIPALITIES, municipality);
                    }
                    final String municipalityCode = directIdpAttribute.getAttributeNS(null, "municipalityCode");
                    if (municipalityCode != null) {
                        idpMappings.put(RestDataConnector.ATTR_ID_MUNICIPALITY_CODE, municipalityCode);
                    }
                    principalMappings.put(idp, idpMappings);
                    builder.addPropertyValue("principalMappings", principalMappings);
                }
            }
            
        }
    }
}