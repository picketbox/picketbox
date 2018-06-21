/*
  * JBoss, Home of Professional Open Source
  * Copyright 2007, JBoss Inc., and individual contributors as indicated
  * by the @authors tag. See the copyright.txt in the distribution for a
  * full listing of individual contributors.
  *
  * This is free software; you can redistribute it and/or modify it
  * under the terms of the GNU Lesser General Public License as
  * published by the Free Software Foundation; either version 2.1 of
  * the License, or (at your option) any later version.
  *
  * This software is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  * Lesser General Public License for more details.
  *
  * You should have received a copy of the GNU Lesser General Public
  * License along with this software; if not, write to the Free
  * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
  * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
  */
package org.jboss.test.security.helpers;

import java.util.Arrays;
import java.util.Random;
import javax.xml.bind.DatatypeConverter;
import junit.framework.TestCase;
import org.jboss.security.Base64Encoder;

/**
 *
 * @author rmartinc
 */
public class Base64UnitTestCase extends TestCase {
    
    private final Random rand;
    
    public Base64UnitTestCase() {
        rand = new Random();
    }
    
    private byte[] generateRandonByteArray(int length) {
        byte[] result = new byte[length];
        rand.nextBytes(result);
        return result;
    }
    
    private void testEOLLine(String message, String base64) {
        for (int i = 76; i < base64.length(); i += 77) {
            assertTrue(message + " pos " + i, base64.charAt(i) == '\n');
        }
    }
    
    private void internalTest(String message, int length) throws Exception{
        byte[] orig = generateRandonByteArray(length);
        String encoded = Base64Encoder.encode(orig);
        testEOLLine(message, encoded);
        String encoded2 = DatatypeConverter.printBase64Binary(orig);
        assertEquals(message, encoded.replace("\n", ""), encoded2);
        byte[] decoded = DatatypeConverter.parseBase64Binary(encoded);
        assertTrue(message, Arrays.equals(orig, decoded));
    }
    
    // test for 1-4 size
    
    public void test1() throws Exception {
        internalTest("size1", 1);
    }
    
    public void test2() throws Exception {
        internalTest("size2", 2);
    }
    
    public void test3() throws Exception {
        internalTest("size3", 3);
    }
    
    public void test4() throws Exception {
        internalTest("size4", 4);
    }
    
    // test around first line break 56, 57
    
    public void test56() throws Exception {
        internalTest("size56", 56);
    }
    
    public void test57() throws Exception {
        internalTest("size57", 57);
    }
    
    // test errors around 1023-1026
    
    public void test1023() throws Exception {
        internalTest("size1023", 1023);
    }
    
    public void test1024() throws Exception {
        internalTest("size1024", 1024);
    }
    
    public void test1025() throws Exception {
        internalTest("size1025", 1025);
    }
    
    public void test1026() throws Exception {
        internalTest("size1026", 1026);
    }
    
    // test 3069-3072
    
    public void test3069() throws Exception {
        internalTest("size3069", 3069);
    }
    
    public void test3070() throws Exception {
        internalTest("size3070", 3070);
    }
    
    public void test3071() throws Exception {
        internalTest("size3071", 3071);
    }
    
    public void test3072() throws Exception {
        internalTest("size3072", 3072);
    }
}
