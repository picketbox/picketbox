/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2008, Red Hat Middleware LLC, and individual contributors
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
package org.jboss.test.security.vault;

import org.jboss.security.plugins.PBEUtils;
import org.jboss.security.vault.SecurityVault;
import org.jboss.security.vault.SecurityVaultFactory;
import org.jboss.security.vault.SecurityVaultUtil;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.picketbox.plugins.vault.PicketBoxSecurityVault;
import org.picketbox.util.StringUtil;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.File;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Unit Test the {@link SecurityVault} Implementation
 * @author Anil.Saldhana@redhat.com
 * @since Aug 12, 2011
 */
public class SecurityVaultUnitTestCase
{ 
   String salt = "12438567";
   int iterationCount = 50; 
   
   String keyStorePass = "vault22";
   
   String maskedPWD;
   
   String dataDir = "${java.io.tmpdir}/enc/";
   
   @Before
   public void setup() throws Exception
   {
      setupEncryptionFilesDir(dataDir);
   }

   private void setupEncryptionFilesDir(String directoryName) {

      String dir = StringUtil.getSystemPropertyAsString(directoryName);
      File encDir = new File(dir);
      
      if(encDir.exists() == false)
         encDir.mkdirs();
      
      File encFile = new File(dir + "/enc.dat");
      if(encFile.exists())
         encFile.delete();
   }
   
   @Test
   @Ignore
   public void testDefaultVault() throws Exception
   {
      SecurityVault vault = SecurityVaultFactory.get();
      assertNotNull(vault);
      assertTrue(vault instanceof PicketBoxSecurityVault);
      assertFalse(vault.isInitialized());
   }
   
   @Test
   @Ignore
   public void testInitialization() throws Exception
   {
      SecurityVault vault = SecurityVaultFactory.get();
      assertNotNull(vault);
      assertTrue(vault instanceof PicketBoxSecurityVault);
      assertFalse(vault.isInitialized());
      
      Map<String,Object> options = new HashMap<String,Object>();
      try
      {
         vault.init(options);
         fail("Should have thrown error"); 
      }
      catch(IllegalArgumentException iae)
      {   
      }
      maskedPWD = getMaskedPassword(keyStorePass, salt,iterationCount);
      
      options.putAll(getMap());
      vault.init(options);
      
      assertTrue(vault.isInitialized());
   }
   
   @Test
   public void testHandshake() throws Exception
   {
      SecurityVault vault = SecurityVaultFactory.get(); 
      Map<String,Object> options = new HashMap<String,Object>(); 
      maskedPWD = getMaskedPassword(keyStorePass, salt,iterationCount);

      options.putAll(getMap());
      
      vault.init(options);
      assertTrue(vault.isInitialized());
      
      Map<String,Object> handshakeOptions = new HashMap<String,Object>();
      handshakeOptions.put(PicketBoxSecurityVault.PUBLIC_CERT,"vault");
      
      byte[] sharedKey = vault.handshake(handshakeOptions);
      assertNotNull(sharedKey);
   }

   @Test
   public void testHandshakeForLongAlias() throws Exception
   {

      SecurityVault vault = SecurityVaultFactory.get();
      String maskedPassword = getMaskedPassword("password1234", "87654321", 23);
      String encDir = "${java.io.tmpdir}/long_alias_keystore/";
      setupEncryptionFilesDir(encDir);

      Map<String,Object> options = new HashMap<String,Object>();
      options.put(PicketBoxSecurityVault.KEYSTORE_URL, "src/test/resources/long_alias_keystore/vault.jks");
      options.put(PicketBoxSecurityVault.KEYSTORE_PASSWORD, maskedPassword);
      options.put(PicketBoxSecurityVault.KEYSTORE_ALIAS, "superverylongvaultname");
      options.put(PicketBoxSecurityVault.SALT, "87654321");
      options.put(PicketBoxSecurityVault.ITERATION_COUNT, String.valueOf(23));
      options.put(PicketBoxSecurityVault.ENC_FILE_DIR, encDir);

      vault.init(options);
      assertTrue("Vault is supposed to be initialized", vault.isInitialized());

      Map<String,Object> handshakeOptions = new HashMap<String,Object>();
      handshakeOptions.put(PicketBoxSecurityVault.PUBLIC_CERT, "superverylongvaultname");

      byte[] sharedKey = vault.handshake(handshakeOptions);
      assertNotNull(sharedKey);

      boolean containsLineBreaks = false;
      for (byte b: sharedKey) {
         if (b == '\n') {
            containsLineBreaks = true;
            break;
         }
      }
      assertFalse("Shared key returned from hadshake cannot contain line break character", containsLineBreaks);
   }
   
   @Test
   public void testStoreAndRetrieve() throws Exception
   {
      String vaultBlock = "SecBean";
      String attributeName = "theAttribute";
      
      char[] attributeValue = "someValue".toCharArray();
      
      SecurityVault vault = SecurityVaultFactory.get(); 
      Map<String,Object> options = new HashMap<String,Object>(); 
      maskedPWD = getMaskedPassword(keyStorePass, salt,iterationCount);

      options.putAll(getMap());
      
      vault.init(options);
      assertTrue(vault.isInitialized());
      
      Map<String,Object> handshakeOptions = new HashMap<String,Object>();
      handshakeOptions.put(PicketBoxSecurityVault.PUBLIC_CERT,"vault");
      
      byte[] sharedKey = vault.handshake(handshakeOptions);
      assertNotNull(sharedKey);
      
      vault.store(vaultBlock, attributeName, attributeValue , sharedKey);
      
      assertTrue(vault.exists(vaultBlock, attributeName));
      //Now retrieve 
      assertEquals(new String(attributeValue), new String(vault.retrieve(vaultBlock, attributeName, sharedKey))); 
      
      vault.store(vaultBlock+"1", attributeName+"2", attributeValue , sharedKey);
      assertEquals(new String(attributeValue), new String(vault.retrieve(vaultBlock+"1", attributeName+"2", sharedKey))); 
      
      System.out.println("Currently storing:" + vault.keyList());
      
      assertTrue(vault.remove(vaultBlock+"1", attributeName+"2", sharedKey));
      assertFalse(vault.exists(vaultBlock+"1", attributeName+"2"));
   }
   
   @Test
   public void testUtil() throws Exception
   {
	   assertFalse(SecurityVaultUtil.isVaultFormat((String)null));
	   assertFalse(SecurityVaultUtil.isVaultFormat((char[])null));
   }
   
   private String getMaskedPassword(String pwd, String salt, int iterationCount) throws Exception
   {
      String algo = "PBEwithMD5andDES";
      
      // Create the PBE secret key 
      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEwithMD5andDES");

      char[] password = "somearbitrarycrazystringthatdoesnotmatter".toCharArray();
      PBEParameterSpec cipherSpec = new PBEParameterSpec(salt.getBytes(), iterationCount);
      PBEKeySpec keySpec = new PBEKeySpec(password);
      SecretKey cipherKey = factory.generateSecret(keySpec);
      
      String maskedPass = PBEUtils.encode64(pwd.getBytes(), algo, cipherKey, cipherSpec);
      
      return new String(PicketBoxSecurityVault.PASS_MASK_PREFIX) + maskedPass; 
   }
   
   private Map<String,Object> getMap()
   { 
      Map<String,Object> options = new HashMap<String,Object>();
      options.put(PicketBoxSecurityVault.KEYSTORE_URL, "src/test/resources/keystore/vault.keystore");
      options.put(PicketBoxSecurityVault.KEYSTORE_PASSWORD, maskedPWD);
      options.put(PicketBoxSecurityVault.KEYSTORE_ALIAS, "vault");
      options.put(PicketBoxSecurityVault.SALT, salt);
      options.put(PicketBoxSecurityVault.ITERATION_COUNT, "" + iterationCount);

      options.put(PicketBoxSecurityVault.ENC_FILE_DIR,dataDir);
      
      return options;
   }
}
