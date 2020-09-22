package fi.mpass.shibboleth.attribute.resolver.data;

import com.google.gson.annotations.SerializedName;

public class School {

	@SerializedName("oppilaitosKoodi")
	private String id;
	
	@SerializedName("nimi")
	private String name;
	
	private String parentOid;
	
	private String parentName;

	public School() {};
	
	public School(String id, String name, String parentOid, String parentName) {
		this.id = id;
		this.name = name;
		this.parentOid = parentOid;
		this.parentName = parentName;
	}
	
	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getParentOid() {
		return parentOid;
	}
	public void setParentOid(String parentOid) {
		this.parentOid = parentOid;
	}
	public String getParentName() {
		return parentName;
	}
	public void setParentName(String parentName) {
		this.parentName = parentName;
	}
}
