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

import java.util.Arrays;

import com.google.gson.annotations.SerializedName;

/**
 * This class represents one school data in Opintopolku API.
 */
public class OpintopolkuOppilaitosDTO {

    /** The code URI value. */
    @SerializedName("koodiUri")
    private String codeUri;
    
    /** The metadata for a school. */
    private OpintopolkuOppilaitosMetadataDTO[] metadata;
    
    /** The version value. */
    @SerializedName("versio")
    private String version;
    
    /** The code value. */
    @SerializedName("koodiArvo")
    private String codeValue;

    private String oid;
    
    private String parentOid;

	private String parentName;

    private String organizationType;
    
    /**
     * Set the code URI value.
     * @param newCodeUri What to set.
     */
    public void setCodeUri(String newCodeUri) {
        codeUri = newCodeUri;
    }
    
    /**
     * Get the code URI value.
     * @return The core URI value.
     */
    public String getCodeUri() {
        return codeUri;
    }
    
    /**
     * Set the code value.
     * @param newCodeValue What to set.
     */
    public void setCodeValue(String newCodeValue) {
        codeValue = newCodeValue;
    }
    
    /**
     * Get the code value.
     * @return The code value.
     */
    public String getCodeValue() {
        return codeValue;
    }
    
    /**
     * Set the metadata for a school.
     * @param newMetadata What to set.
     */
    public void setMetadata(OpintopolkuOppilaitosMetadataDTO[] newMetadata) {
        metadata = newMetadata;
    }
    
    /**
     * Get the metadata for a school.
     * @return The metadata for a school.
     */
    public OpintopolkuOppilaitosMetadataDTO[] getMetadata() {
        return metadata;
    }

    /**
     * Set the version.
     * @param newVersion What to set.
     */
    public void setVersion(String newVersion) {
        version = newVersion;
    }
    
    /**
     * Get the version.
     * @return The version.
     */
    public String getVersion() {
        return version;
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

    public String getOrganizationType() {
        return organizationType;
    }

    public void setOrganizationType(String organizationType) {
        this.organizationType = organizationType;
    }

    public String getOid() {
        return oid;
    }

    public void setOid(String oid) {
        this.oid = oid;
    }

    @Override
    public String toString() {
        return "OpintopolkuOppilaitosDTO [codeUri=" + codeUri + ", metadata=" + Arrays.toString(metadata) + ", version="
                + version + ", codeValue=" + codeValue + ", oid=" + oid + ", parentOid=" + parentOid + ", parentName="
                + parentName + ", organizationType=" + organizationType + "]";
    }

    
}
