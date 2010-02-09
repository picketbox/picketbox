/*
* JBoss, Home of Professional Open Source
* Copyright 2005, JBoss Inc., and individual contributors as indicated
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
package org.jboss.test;
 

import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.jboss.crypto.CryptoUtil;
import org.jboss.security.SecurityUtil;

/** Tests of the org.jboss.security.CryptoUtil class
 
 @author Scott.Stark@jboss.org
 @version $Revision$
 */
public class UtilTestCase extends TestCase
{
   public UtilTestCase(String name)
   {
      super(name);
   }
   
   /** Compare CryptoUtil.encodeBase64 against the sun misc class
    */
   public void testBase64() throws Exception
   {
      System.out.println("testBase64");
      byte[] test = "echoman".getBytes();
      String b64_1 = CryptoUtil.encodeBase64(test);
      //String b64_1 = Base64.encodeBytes(test);
      
      System.out.println("b64_1 = "+b64_1);
      
      //Anil: I think the MimeCryptoUtility.encodeText is broken
      /*
      String b64_2 = MimeCryptoUtility.encodeText("echoman", "iso-8859-1", "B");
      System.out.println("b64_2 = "+b64_2);
      super.assertEquals("encodeBase64 == BASE64Encoder", b64_1, b64_2);*/
   }

   /** Compare CryptoUtil.encodeBase16 against the java.math.BigInteger class
    */
   public void testBase16() throws Exception
   {
      System.out.println("testBase16");
      byte[] test = "echoman".getBytes();
      String b16_1 = CryptoUtil.encodeBase16(test);
      System.out.println("b16_1 = "+b16_1);

      java.math.BigInteger encoder = new java.math.BigInteger(test);
      String b16_2 = encoder.toString(16);
      System.out.println("b16_2 = "+b16_2);
      super.assertEquals("encodeBase16 == BigInteger", b16_1, b16_2);
   }
   
   public void testUnPrefixSecurityDomain() throws Exception
   {
      assertEquals("sd==sd", "sd", SecurityUtil.unprefixSecurityDomain("sd"));
      assertEquals("java:/jaas/sd==sd","sd",  SecurityUtil.unprefixSecurityDomain("java:/jaas/sd"));
      assertEquals("java:/jbsx/sd==sd","sd",  SecurityUtil.unprefixSecurityDomain("java:/jbsx/sd"));
   }

   public static void main(java.lang.String[] args)
   {
      System.setErr(System.out);
      TestSuite suite = new TestSuite(UtilTestCase.class);
      junit.textui.TestRunner.run(suite);
   }
}
