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
 * This class defines the {@link TypeAdapter} needed when deserializing {@link RolesDTO} from Json.
 */
public class RolesTypeAdapter extends TypeAdapter<RolesDTO>{
	
	private final Logger logger = LoggerFactory.getLogger(RolesTypeAdapter.class);

	@Override
	public void write(JsonWriter out, RolesDTO roles) throws IOException {
		out.beginObject();
		out.name("shcool");
		out.value(roles.getSchool());
		out.name("role");
		out.value(roles.getRole());
		out.name("group");
		out.value(roles.getGroup());
		out.name("groupLevel");
		out.value(roles.getGroupLevel());
		out.name("municipality");
		out.value(roles.getMunicipality());
	}
	
	@Override
	public RolesDTO read(JsonReader in) throws IOException {
		
		RolesDTO roles = new UserDTO().new RolesDTO();
		
		in.beginObject();
		String fieldName = null;
		
		while (in.hasNext()) {
			JsonToken token = in.peek();
			
			if (token.equals(JsonToken.NAME)) {
				fieldName = in.nextName();
			}
			
			if ("school".equals(fieldName)) {
				token = in.peek();
				roles.setSchool(in.nextString());
			}
			
			if ("role".equals(fieldName)) {
				token = in.peek();
				roles.setRole(in.nextString());
			}
			
			if ("group".equals(fieldName)) {
				token = in.peek();
				roles.setGroup(in.nextString());
			}
			
			if ("groupLevel".equals(fieldName)) {
				token = in.peek();
				try {
					roles.setGroupLevel(in.nextInt());
				}
				catch (IllegalStateException | NumberFormatException e) {
					logger.warn("Group level is not int: {}", in.nextString());
				};
			}
			
			if ("municipality".equals(fieldName)) {
				token = in.peek();
				roles.setMunicipality(in.nextString());
			}
		}
		
		in.endObject();
		return roles;
	}

}
