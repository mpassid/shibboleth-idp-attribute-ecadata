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

import com.google.gson.annotations.SerializedName;

/**
 * This class represents one school metadata in Opintopolku API.
 */
public class OpintopolkuOppilaitosMetadataDTO {

    /** The name of the school. */
    @SerializedName("nimi")
    private String name;
    
    /** The short name of the school. */
    @SerializedName("lyhytNimi")
    private String shortName;
    
    /** The language of the school. */
    @SerializedName("kieli")
    private String language;
    
    /**
     * Set the name of the school.
     * @param newName What to set.
     */
    public void setName(String newName) {
        name = newName;
    }
    
    /**
     * Get the name of the school.
     * @return The name of the school.
     */
    public String getName() {
        return name;
    }

    /**
     * Set the short name of the school.
     * @param newShortName What to set.
     */
    public void setShortName(String newShortName) {
        shortName = newShortName;
    }
    
    /**
     * Get the short name of the school.
     * @return The short name of the school.
     */
    public String getShortName() {
        return shortName;
    }

    /**
     * Set the language of the school.
     * @param newLanguage What to set.
     */
    public void setLanguage(String newLanguage) {
        language = newLanguage;
    }
    
    /**
     * Get the language of the school.
     * @return The language of the school.
     */
    public String getLanguage() {
        return language;
    }

    @Override
    public String toString() {
        return "OpintopolkuOppilaitosMetadataDTO [name=" + name + ", shortName=" + shortName + ", language=" + language
                + "]";
    }  
    
    
}
