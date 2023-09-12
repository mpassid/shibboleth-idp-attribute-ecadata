package fi.mpass.shibboleth.attribute.resolver.data;

import com.google.gson.annotations.SerializedName;

public class School {

	@SerializedName("oppilaitosKoodi")
	private String id;
	
	@SerializedName("nimi")
	private String name;
	
	private String oid;

	private String officeOid;

	private String officeName;

	private String parentOid;
	
	private String parentName;

	private String organizationType;

	public School() {};
	
	public School(String id, String name, String parentOid, String parentName) {
		this.id = id;
		this.name = name;
		this.parentOid = parentOid;
		this.parentName = parentName;
	}

	public School(String id, String name, String oid, String parentOid, String parentName) {
		this.id = id;
		this.oid = oid;
		this.name = name;
		this.parentOid = parentOid;
		this.parentName = parentName;
	}

	public School(String id, String name, String oid, String officeOid, String officeName, String parentOid,
			String parentName, String organizationType) {
		this.id = id;
		this.name = name;
		this.oid = oid;
		this.officeOid = officeOid;
		this.officeName = officeName;
		this.parentOid = parentOid;
		this.parentName = parentName;
		this.organizationType = organizationType;
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

	public String getOid() {
		return oid;
	}

	public void setOid(String oid) {
		this.oid = oid;
	}

	public String getOfficeOid() {
		return officeOid;
	}

	public void setOfficeOid(String officeOid) {
		this.officeOid = officeOid;
	}

	public String getOfficeName() {
		return officeName;
	}

	public void setOfficeName(String officeName) {
		this.officeName = officeName;
	}

	public String getOrganizationType() {
		return organizationType;
	}

	public void setOrganizationType(String organizationType) {
		this.organizationType = organizationType;
	}

	@Override
	public String toString() {
		return "School [id=" + id + ", name=" + name + ", oid=" + oid + ", officeOid=" + officeOid + ", officeName="
				+ officeName + ", parentOid=" + parentOid + ", parentName=" + parentName + ", organizationType="
				+ organizationType + "]";
	}

	
}
