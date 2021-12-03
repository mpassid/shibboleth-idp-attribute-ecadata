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

import javax.annotation.Nonnull;

import com.google.gson.annotations.SerializedName;

import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * This class defines the data transfer object for the communication with ECA
 * Auth Data API. The structure is defined at:
 * https://github.com/educloudalliance/educloud-roledb
 * 
 * An example of a single user:
 * 
 * { "username": "123abc", "first_name": "Teppo", "last_name": "Testaaja",
 * "roles": [ { "school": "17392", "role": "teacher", "group": "7A",
 * "groupLevel": 7 } ] "attributes": [ { "attribute1_id": "attribute1_data",
 * "attribute2_id": "attribute2_data" } ] }
 */
public class UserDTO {

	/** The username. */
	private String username;

	/** The first name of the user. */
	@SerializedName("first_name")
	private String firstName;

	/** The surname of the user. */
	@SerializedName("last_name")
	private String lastName;

	/** The array of roles for the user. */
	private RolesDTO[] roles;

	/** The array of attributes for the user. */
	private AttributesDTO[] attributes;

	/** Return AttributesDTO by name */
	public AttributesDTO getAttribute(@Nonnull final String attributeName) {

		Constraint.isNotNull(attributeName, "Attribute name cannot be null.");

		for (AttributesDTO attr : attributes) {
			if (attr.getName().equals(attributeName)) {
				return attr;
			}
		}
		return null;
	}

	/**
	 * This class defines the role -part of the user data transfer object.
	 */
	public class RolesDTO {

		/** The school corresponding to the role. */
		private String school;

		/** The role attribute. */
		private String role;

		/** The group corresponding to the role. */
		private String group;

		/** The municipality corresponding to the role. */
		private String municipality;

		/** The group level corresponding to the role. */
		private Integer groupLevel;

		/**
		 * Set school.
		 * 
		 * @param newSchool The value to be set.
		 */
		public void setSchool(String newSchool) {
			school = newSchool;
		}

		/**
		 * Get school.
		 * 
		 * @return The value of school.
		 */
		public String getSchool() {
			return school;
		}

		/**
		 * Set role.
		 * 
		 * @param newRole The value to be set.
		 */
		public void setRole(String newRole) {
			role = newRole;
		}

		/**
		 * Get role.
		 * 
		 * @return The value of role.
		 */
		public String getRole() {
			return role;
		}

		/**
		 * Set group.
		 * 
		 * @param newGroup The value to be set.
		 */
		public void setGroup(String newGroup) {
			group = newGroup;
		}

		/**
		 * Get group.
		 * 
		 * @return The value of group.
		 */
		public String getGroup() {
			return group;
		}

		/**
		 * Set municipality.
		 * 
		 * @param newMunicipality The value to be set.
		 */
		public void setMunicipality(String newMunicipality) {
			municipality = newMunicipality;
		}

		/**
		 * Get municipality.
		 * 
		 * @return The value of municipality.
		 */
		public String getMunicipality() {
			return municipality;
		}

		/**
		 * Set group level.
		 * 
		 * @param newGroupLevel The value to be set.
		 */
		public void setGroupLevel(Integer newGroupLevel) {
			groupLevel = newGroupLevel;
		}

		/**
		 * Get group level.
		 * 
		 * @return The value of group level.
		 */
		public Integer getGroupLevel() {
			return groupLevel;
		}

		public String toString() {
			return "Group: " + group + ", GroupLevel: " + groupLevel + ", Municipality: " + municipality + ", Role: "
					+ role + ", School Code: " + school;
		}
	}

	/**
	 * This class defines the attribute -part of the user data transfer object.
	 */
	public class AttributesDTO {

		/** The name of the attribute. */
		private String name;

		/** The value of the attribute. */
		private String value;

		/**
		 * Set name.
		 * 
		 * @param newName The value to be set.
		 */
		public void setName(String newName) {
			name = newName;
		}

		/**
		 * Get name.
		 * 
		 * @return The value of name.
		 */
		public String getName() {
			return name;
		}

		/**
		 * Set value.
		 * 
		 * @param newValue The value to be set.
		 */
		public void setValue(String newValue) {
			value = newValue;
		}

		/**
		 * Get value.
		 * 
		 * @return The value of value.
		 */
		public String getValue() {
			return value;
		}
	}

	/**
	 * Set username.
	 * 
	 * @param newUsername The value to be set.
	 */
	public void setUsername(String newUsername) {
		username = newUsername;
	}

	/**
	 * Get username.
	 * 
	 * @return The value of username.
	 */
	public String getUsername() {
		return username;
	}

	/**
	 * Get first name.
	 * 
	 * @return The value of first_name.
	 */
	public String getFirstName() {
		return firstName;
	}

	/**
	 * Set first name.
	 * 
	 * @param newFirstName The value to be set.
	 */
	public void setFirstName(String newFirstName) {
		this.firstName = newFirstName;
	}

	/**
	 * Get last name.
	 * 
	 * @return The value of last_name.
	 */
	public String getLastName() {
		return lastName;
	}

	/**
	 * Set last name.
	 * 
	 * @param newLastName The value to be set.
	 */
	public void setLastName(String newLastName) {
		this.lastName = newLastName;
	}

	/**
	 * Get roles.
	 * 
	 * @return The value of roles.
	 */
	public RolesDTO[] getRoles() {
		return roles;
	}

	/**
	 * Set roles.
	 * 
	 * @param newRoles The value to be set.
	 */
	public void setRoles(RolesDTO[] newRoles) {
		this.roles = newRoles;
	}

	/**
	 * Get attributes.
	 * 
	 * @return The value of attributes.
	 */
	public AttributesDTO[] getAttributes() {
		return attributes;
	}

	/**
	 * Set attributes.
	 * 
	 * @param newAttributes The value to be set.
	 */
	public void setAttributes(AttributesDTO[] newAttributes) {
		this.attributes = newAttributes;
	}
}