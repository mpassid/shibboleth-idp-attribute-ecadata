package fi.mpass.shibboleth.attribute.resolver.data;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;

import fi.mpass.shibboleth.attribute.resolver.data.UserDTO.RolesDTO;

/**
 * Converts {@link RolesDTO} object to and from JSON. Class extends {@link TypeAdapter}.
 */
public class RolesTypeAdapter extends TypeAdapter<RolesDTO>{
	
	private final Logger logger = LoggerFactory.getLogger(RolesTypeAdapter.class);

	/**
	 * Writes one RolesDTO object for value.
	 * 
	 * @param roles the {@link RolesDTO} object to write. May be null.
	 */
	@Override
	public void write(JsonWriter out, RolesDTO roles) throws IOException {
		out.beginObject();
		out.name("school");
		out.value(roles.getSchool());
		out.name("role");
		out.value(roles.getRole());
		out.name("group");
		out.value(roles.getGroup());
		out.name("groupLevel");
		out.value(roles.getGroupLevel());
		out.name("learningMaterialsCharge");
		out.value(roles.getLearningMaterialsCharge());
		out.name("municipality");
		out.value(roles.getMunicipality());
	}
	
	/**
	 * Reads one JSON value and converts it to a {@link RolesDTO} object. Null values are skipped.
	 * 
	 * @return the converted {@link RolesDTO} object.
	 * @throws IOExection
	 */
	@Override
	public RolesDTO read(JsonReader in) throws IOException {
		
		RolesDTO roles = new UserDTO().new RolesDTO();
		
		in.beginObject();
		String fieldName = null;
		
		while (in.hasNext()) {
			
			if (in.peek() == JsonToken.NAME) {
				fieldName = in.nextName();
			}
			
			if (in.peek() == JsonToken.NULL) {
				in.nextNull();
				continue;
			}
			
			switch(fieldName) {
				case "school" : { roles.setSchool(in.nextString()); break; }
				case "role" : { roles.setRole(in.nextString()); break; }
				case "group" : { roles.setGroup(in.nextString()); break; }
				case "groupLevel" : { 
					try {
						roles.setGroupLevel(in.nextInt());
					}
					catch (IllegalStateException | NumberFormatException e) {
						logger.warn("Group level is not int: {}", in.nextString());
					};
					break;
				}
				case "learningMaterialsCharge" : { 
					try {
						roles.setLearningMaterialsCharge(in.nextInt());
					}
					catch (IllegalStateException | NumberFormatException e) {
						logger.warn("Learning materials charge is not int: {}", in.nextString());
					};
					break;
				}
				case "municipality" : { roles.setMunicipality(in.nextString()); break; }
				default: in.nextString(); break;
			}
		}
		
		in.endObject();
		return roles;
	}
}
