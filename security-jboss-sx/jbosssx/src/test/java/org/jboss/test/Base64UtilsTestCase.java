/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
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

package org.jboss.test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.ByteArrayOutputStream;

import org.jboss.security.Base64Utils;
import org.junit.Test;

/**
 * Tests for {@link Base64Utils} class.
 * 
 * @author Josef Cacek
 */
public class Base64UtilsTestCase
{

   @Test
   public void leadingZeroKeyTest()
   {
      final byte[] leadingZeroKey = new byte[] { 0, 81, 121, -37, 46, -64, 20, 114 };
      final String b64EncLeadinZeroKey = "01HUTikm1Ho";
      assertEquals(b64EncLeadinZeroKey, Base64Utils.tob64(leadingZeroKey));
      assertArrayEquals(leadingZeroKey, Base64Utils.fromb64(b64EncLeadinZeroKey));
   }

   @Test
   public void paddedLeadingZeroKeyTest()
   {
      final byte[] key = new byte[] { 0, 81, 121, -37, 46, -64, 20, 114 };
      final String b64Key = "_01HUTikm1Ho";
      assertEquals(b64Key, Base64Utils.tob64(key, true));
      assertArrayEquals(key, Base64Utils.fromb64(b64Key));
   }

   @Test
   public void lastZeroTest()
   {
      final byte[] key = new byte[] { 114, 81, 121, -37, 46, -64, 20, 0 };
      final String b64Key = "79HUTikm1G0";
      assertEquals(b64Key, Base64Utils.tob64(key));
      assertArrayEquals(key, Base64Utils.fromb64(b64Key));
   }

   @Test
   public void emptyKeyTest()
   {
      final byte[] key = new byte[] {};
      final String b64Key = "";
      assertEquals(b64Key, Base64Utils.tob64(key, true));
      assertEquals(b64Key, Base64Utils.tob64(key, false));
      assertArrayEquals(key, Base64Utils.fromb64(b64Key));
   }

   @Test
   public void paddingTest()
   {
      ByteArrayOutputStream baos = new ByteArrayOutputStream(4);
      baos.write(0);
      assertEquals("__00", Base64Utils.tob64(baos.toByteArray(), true));
      baos.write(0);
      assertEquals("_000", Base64Utils.tob64(baos.toByteArray(), true));
      baos.write(0);
      assertEquals("0000", Base64Utils.tob64(baos.toByteArray(), true));
      baos.write(0);
      assertEquals("__000000", Base64Utils.tob64(baos.toByteArray(), true));
      baos.write(0);
//      assertArrayEquals(new byte[] {115, 117, 114, 101, 46}, Base64Utils.fromb64("_c3VyZS4"));
   }

   
   @Test
   public void encodeDecodeTest() {
      doEncodeDecodeTest(generateData(252));
      doEncodeDecodeTest(generateData(253));
      doEncodeDecodeTest(generateData(254));
      doEncodeDecodeTest(generateData(255));
   }
   
   private void doEncodeDecodeTest(byte[] inputData) {
 
      String s = Base64Utils.tob64(inputData); 
      String sp = Base64Utils.tob64(inputData, true);

      byte[] decoded = Base64Utils.fromb64(s);
      byte[] decodedp = Base64Utils.fromb64(sp);
       
      //assertTrue("Whole result data has to be within the range for base64", isInRange(result));

      assertArrayEquals("Encode-Decode test failed, results are not the same.", inputData, decoded);
      assertArrayEquals("Encode-Decode test for padding failed, results are not the same.", inputData, decodedp);
   }
   
   private byte[] generateData(final int len) {
       byte[] data = new byte[len];
       for (int i = 0; i < len ; i++) {
           data[i] = (byte)i;
       }
       return data;
   }
   
}
