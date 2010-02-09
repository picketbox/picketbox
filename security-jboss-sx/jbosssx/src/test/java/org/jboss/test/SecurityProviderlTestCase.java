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

import java.security.MessageDigest;
import java.security.Security;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.jboss.crypto.CryptoUtil;
import org.jboss.crypto.JBossSXProvider;

/** Tests of the org.jboss.crypto.*  Java Cryptography Architecture plugin
 classes
 
 @author Scott.Stark@jboss.org
 @version $Revision$
 */
public class SecurityProviderlTestCase extends TestCase
{
   public SecurityProviderlTestCase(String name)
   {
      super(name);
   }
   
   /** Compare Util.sessionKeyHash against the SHA-SRP MessageDigest. This
    will not match the Util.sessionKeyHash as the algorithm described in
    RFC2945 does not reverse the odd and even byte arrays as is done in
    Util.sessionKeyHash.
    */
   public void testSHAInterleave() throws Exception
   {
      System.out.println("testSHAInterleave");
      MessageDigest md = MessageDigest.getInstance("SHA-SRP");
      byte[] test = "session_key".getBytes();

      byte[] hash1 = CryptoUtil.sessionKeyHash(test);
      String hash1b64 = CryptoUtil.encodeBase64(hash1);
      System.out.println("hash1 = "+hash1b64);
      byte[] hash2 = md.digest(test);
      String hash2b64 = CryptoUtil.encodeBase64(hash2);
      System.out.println("hash2 = "+hash2b64);
      super.assertTrue(hash1b64.equals(hash2b64) == false);
   }
   /** This should match the CryptoUtil.sessionKeyHash
    */
   public void testSHAReverseInterleave() throws Exception
   {
      System.out.println("testSHAReverseInterleave");
      MessageDigest md = MessageDigest.getInstance("SHA-SRP-Reverse");
      byte[] test = "session_key".getBytes();

      byte[] hash1 = CryptoUtil.sessionKeyHash(test);
      String hash1b64 = CryptoUtil.encodeBase64(hash1);
      System.out.println("hash1 = "+hash1b64);
      byte[] hash2 = md.digest(test);
      String hash2b64 = CryptoUtil.encodeBase64(hash2);
      System.out.println("hash2 = "+hash2b64);
      super.assertEquals(hash1b64, hash2b64);
   }

   public static Test suite()
   {
      TestSuite suite = new TestSuite(SecurityProviderlTestCase.class);

      // Create an initializer for the test suite
      TestSetup wrapper = new TestSetup(suite)
      {
         protected void setUp() throws Exception
         {
            CryptoUtil.init();
            JBossSXProvider provider = new JBossSXProvider();
            Security.addProvider(provider);
         }
         protected void tearDown() throws Exception
         {
            Security.removeProvider(JBossSXProvider.PROVIDER_NAME);
         }
      };
      return wrapper;
   }

   public static void main(java.lang.String[] args)
   {
      System.setErr(System.out);
      Test suite = suite();
      junit.textui.TestRunner.run(suite);
   }
}
