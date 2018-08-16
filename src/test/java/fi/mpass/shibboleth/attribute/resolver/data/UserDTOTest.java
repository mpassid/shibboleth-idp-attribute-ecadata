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

package fi.mpass.shibboleth.attribute.resolver.data;

import java.io.InputStreamReader;
import java.io.Reader;

import org.testng.Assert;
import org.testng.annotations.Test;

import com.google.gson.Gson;

import fi.mpass.shibboleth.attribute.resolver.data.UserDTO;
import fi.mpass.shibboleth.attribute.resolver.data.UserDTO.AttributesDTO;
import fi.mpass.shibboleth.attribute.resolver.data.UserDTO.RolesDTO;

/**
 * Unit testing for {@link UserDTO} using Gson.
 */
public class UserDTOTest {
    
    /**
     * Tests class methods directly without JSON parsing.
     */
    @Test
    public void testWithoutJson() {
        final UserDTO user = new UserDTO();
        Assert.assertNull(user.getFirstName());
        Assert.assertNull(user.getLastName());
        Assert.assertNull(user.getUsername());
        Assert.assertNull(user.getAttributes());
        Assert.assertNull(user.getRoles());
        
        final AttributesDTO attributes = user.new AttributesDTO();
        Assert.assertNull(attributes.getName());
        Assert.assertNull(attributes.getValue());
        
        final RolesDTO roles = user.new RolesDTO();
        Assert.assertNull(roles.getGroup());
        Assert.assertNull(roles.getMunicipality());
        Assert.assertNull(roles.getRole());
        Assert.assertNull(roles.getSchool());
        
        final String firstName = "mockFirstName";
        final String lastName = "mockLastName";
        final String username = "mockUsername";
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setUsername(username);
        Assert.assertEquals(user.getFirstName(), firstName);
        Assert.assertEquals(user.getLastName(), lastName);
        Assert.assertEquals(user.getUsername(), username);

        final String name = "mockName";
        final String value = "mockValue";
        attributes.setName(name);
        attributes.setValue(value);
        assertAttribute(attributes, name, value);
        
        final String group = "mockGroup";
        final String municipality = "mockMunicipality";
        final String role = "mockRole";
        final String school = "mockSchool";
        roles.setGroup(group);
        roles.setMunicipality(municipality);
        roles.setRole(role);
        roles.setSchool(school);
        assertRole(roles, group, municipality, role, school);
        
        user.setAttributes(new AttributesDTO[] { attributes });
        user.setRoles(new RolesDTO[] { roles });
        Assert.assertEquals(user.getAttributes().length, 1);
        Assert.assertEquals(user.getRoles().length, 1);
        assertAttribute(user.getAttributes()[0], name, value);
        assertRole(user.getRoles()[0], group, municipality, role, school);
    }
    
    /**
     * Verifies attribute's contents.
     * @param attribute
     * @param name
     * @param value
     */
    public void assertAttribute(final AttributesDTO attribute, final String name, final String value) {
        Assert.assertEquals(attribute.getName(), name);
        Assert.assertEquals(attribute.getValue(), value);        
    }
    
    /**
     * Verifies role's contents.
     * @param role
     * @param group
     * @param municipality
     * @param roleStr
     * @param school
     */
    public void assertRole(final RolesDTO role, final String group, final String municipality, final String roleStr, final String school) {
        Assert.assertEquals(role.getGroup(), group);
        Assert.assertEquals(role.getMunicipality(), municipality);
        Assert.assertEquals(role.getRole(), roleStr);
        Assert.assertEquals(role.getSchool(), school);        
    }

    /**
     * Tests parsing of a single user data transfer object without roles nor attributes.
     */
    @Test
    public void testNoRolesNoAttributes() {
        UserDTO user = getUser("user-0role-0attr.json");
        Assert.assertEquals(user.getUsername(), "OID1");
        Assert.assertEquals(user.getFirstName(), "John");
        Assert.assertEquals(user.getLastName(), "Doe");
        Assert.assertNull(user.getRoles());
        Assert.assertNull(user.getAttributes());
    }
    
    /**
     * Tests parsing of a single user data transfer object with one role and one attribute.
     */
    @Test
    public void testOneRoleOneAttribute() {
        UserDTO user = getUser("user-1role-1attr.json");
        Assert.assertEquals(user.getUsername(), "OID1");
        Assert.assertEquals(user.getFirstName(), "John");
        Assert.assertEquals(user.getLastName(), "Doe");
        Assert.assertEquals(user.getRoles().length, 1);
        Assert.assertEquals(user.getRoles()[0].getRole(), "teacher");
        Assert.assertEquals(user.getRoles()[0].getSchool(), "12345");
        Assert.assertEquals(user.getRoles()[0].getGroup(), "7C");
        Assert.assertEquals(user.getRoles()[0].getMunicipality(), "Great City");
        Assert.assertEquals(user.getAttributes().length, 1);
        Assert.assertEquals(user.getAttributes()[0].getName(), "google");
        Assert.assertEquals(user.getAttributes()[0].getValue(), "11XxjGZOeAyNqwTdq0Xec9ydDhYoq5CHrTQXHHSfGWM=");
    }

    /**
     * Tests parsing of a single user data transfer object with two roles and two attributes.
     */
    @Test
    public void testTwoRoleTwoAttribute() {
        UserDTO user = getUser("user-2role-2attr.json");
        Assert.assertEquals(user.getUsername(), "OID1");
        Assert.assertEquals(user.getFirstName(), "John");
        Assert.assertEquals(user.getLastName(), "Doe");
        Assert.assertEquals(user.getRoles().length, 2);
        Assert.assertEquals(user.getRoles()[0].getRole(), "teacher");
        Assert.assertEquals(user.getRoles()[0].getSchool(), "12345");
        Assert.assertEquals(user.getRoles()[0].getGroup(), "7C");
        Assert.assertEquals(user.getRoles()[0].getMunicipality(), "Great City");
        Assert.assertEquals(user.getRoles()[1].getRole(), "teacher");
        Assert.assertEquals(user.getRoles()[1].getSchool(), "23456");
        Assert.assertEquals(user.getRoles()[1].getGroup(), "9B");
        Assert.assertEquals(user.getRoles()[1].getMunicipality(), "Rival City");
        Assert.assertEquals(user.getAttributes().length, 2);
        Assert.assertEquals(user.getAttributes()[0].getName(), "google");
        Assert.assertEquals(user.getAttributes()[0].getValue(), "11XxjGZOeAyNqwTdq0Xec9ydDhYoq5CHrTQXHHSfGWM=");
        Assert.assertEquals(user.getAttributes()[1].getName(), "twitter");
        Assert.assertEquals(user.getAttributes()[1].getValue(), "88XxjGZOeAyNqwTdq0Xec9ydDhYoq5CHrTQXHHSfGWM=");
    }

    /**
     * Parses a user object from the given class path resource.
     * 
     * @param classResource The resource containing user JSON.
     * @return The user object.
     */
    protected UserDTO getUser(String classResource) {
        Gson gson = new Gson();
        Reader reader = new InputStreamReader(this.getClass().getResourceAsStream(classResource));
        return gson.fromJson(reader, UserDTO.class);
    }
}