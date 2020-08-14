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

import org.testng.Assert;
import org.testng.annotations.Test;

import com.google.gson.Gson;

/**
 * Unit tests for {@link OpintopolkuOppilaitosDTO} and {@link OpintopolkuOppilaitosMetadataDTO}.
 */
public class OpintopolkuGsonEncodeDecodeTest {
    
    @Test
    public void testEncodeDecode() throws Exception {
        final String codeUri = "mockCodeUri";
        final String name = "mockName";
        final String shortName = "mockShortName";
        final String language = "mockLanguage";
        final String version = "1";
        final String codeValue = "123456";
        OpintopolkuOppilaitosDTO oppilaitos = new OpintopolkuOppilaitosDTO();
        oppilaitos.setCodeUri(codeUri);
        oppilaitos.setCodeValue(codeValue);
        oppilaitos.setVersion(version);
        OpintopolkuOppilaitosMetadataDTO metadata = new OpintopolkuOppilaitosMetadataDTO();
        metadata.setLanguage(language);
        metadata.setName(name);
        metadata.setShortName(shortName);
        oppilaitos.setMetadata(new OpintopolkuOppilaitosMetadataDTO[] { metadata });
        Gson gson = new Gson();
        final String encoded = gson.toJson(oppilaitos);
        final OpintopolkuOppilaitosDTO decoded = gson.fromJson(encoded, OpintopolkuOppilaitosDTO.class);
        Assert.assertEquals(decoded.getCodeUri(), codeUri);
        Assert.assertEquals(decoded.getCodeValue(), codeValue);
        Assert.assertEquals(decoded.getVersion(), version);
        Assert.assertEquals(decoded.getMetadata().length, 1);
        Assert.assertEquals(decoded.getMetadata()[0].getLanguage(), language);
        Assert.assertEquals(decoded.getMetadata()[0].getName(), name);
        Assert.assertEquals(decoded.getMetadata()[0].getShortName(), shortName);
    }
}
