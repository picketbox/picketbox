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

import org.jboss.security.Util;
import org.jboss.security.plugins.PBEUtils;
import org.jboss.security.vault.SecurityVault;
import org.jboss.security.vault.SecurityVaultException;
import org.jboss.security.vault.SecurityVaultFactory;
import org.jboss.security.vault.SecurityVaultUtil;
import org.jboss.test.SecurityActions;
import org.junit.Assume;
import org.junit.Test;
import org.picketbox.plugins.vault.PicketBoxSecurityVault;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.channels.FileChannel;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Unit Test the {@link SecurityVault} Implementation
 * 
 * Note: replacement-vault.keystore has been created using: 
 *       keytool -genkey -alias mykey -keystore replacement-vault.keystore -keyalg RSA -keysize 1024 -storepass supersecret11 -keypass supersecret11 -dname "CN=Picketbox vault,OU=picketbox,O=JBoss"
 *       
 * @author Anil.Saldhana@redhat.com
 * @since Aug 12, 2011
 */
public class SecurityVaultUnitTestCase
{ 
   //String dataDir = "${java.io.tmpdir}/enc/";
   
   @Test
   public void testDefaultVault() throws Exception
   {
      SecurityVault vault = SecurityVaultFactory.get();
      assertNotNull(vault);
      assertTrue(vault instanceof PicketBoxSecurityVault);
      assertFalse(vault.isInitialized());
   }

   @Test
   public void testClassLoaderVault() throws Exception
   {
      //Back up the existing vault and reset it
      Field field = SecurityVaultFactory.class.getDeclaredField("vault");
      field.setAccessible(true);
      Object existingVault = field.get(null);
      try
      {
         field.set(null, null);
         ClassLoader cl = SecurityVaultFactory.class.getClassLoader();
         SecurityVault vault = SecurityVaultFactory.get(cl, TestVault.class.getName());
         assertNotNull(vault);
         assertTrue(vault instanceof TestVault);
         assertFalse(vault.isInitialized());
      }
      finally
      {
         if (existingVault != null)
         {
            field.set(null, existingVault);
         }
      }
   }
   
   @Test
   public void testHandshake() throws Exception
   {
      
      setInitialVaulConditions("src/test/resources/keystore/vault.jks", "target/vaults/vault1/vault.jks", 
            "src/test/resources/keystore/vault_data", "target/vaults/vault1/vault_data");
      
      SecurityVault vault = getNewSecurityVaultInstance(); 
      Map<String,Object> options = getVaultOptionsMap(
            "target/vaults/vault1/vault.jks", 
            "target/vaults/vault1/vault_data", 
            "vault", "12438567", 50, "vault22"); 
            
      vault.init(options);
      assertTrue(vault.isInitialized());
      
      Map<String,Object> handshakeOptions = new HashMap<String,Object>();
      handshakeOptions.put(PicketBoxSecurityVault.PUBLIC_CERT,"vault");
      
      byte[] sharedKey = vault.handshake(handshakeOptions);
      assertNotNull(sharedKey);
   }
   
   @Test
   public void testHandshakeAnConversionForLongAlias() throws Exception
   {
      setInitialVaulConditions("src/test/resources/long_alias_keystore/vault.jks", "target/vaults/long_alias_keystore/vault.jks", 
            "src/test/resources/long_alias_keystore/vault_data", "target/vaults/long_alias_keystore/vault_data");
      
      SecurityVault vault = getNewSecurityVaultInstance(); 
      Map<String,Object> options = getVaultOptionsMap(
            "target/vaults/long_alias_keystore/vault.jks", 
            "target/vaults/long_alias_keystore/vault_data", 
            "superverylongvaultname", "87654321", 23, "password1234"); 

      vault.init(options);
      assertTrue("Vault is supposed to be inicialized", vault.isInitialized());
      
      Map<String,Object> handshakeOptions = new HashMap<String,Object>();
      byte[] sharedKey = vault.handshake(handshakeOptions);
      assertNotNull(sharedKey);

      // not relevant anymore, but leaving it as is 
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

      setInitialVaulConditions("src/test/resources/keystore/vault.jks", "target/vaults/vault2/vault.jks", 
            "src/test/resources/keystore/vault_data", "target/vaults/vault2/vault_data");
      
      Map<String,Object> options = getVaultOptionsMap(
            "target/vaults/vault2/vault.jks", 
            "target/vaults/vault2/vault_data", 
            "vault", "12438567", 50, "vault22"); 

      String vaultBlock = "SecBean";
      String attributeName = "theAttribute";
      
      char[] attributeValue = "someValue".toCharArray();
      
      SecurityVault vault = getNewSecurityVaultInstance();

      vault.init(options);
      assertTrue(vault.isInitialized());
      
      Map<String,Object> handshakeOptions = new HashMap<String,Object>();
      
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
   public void testClassBasedKeystorePassword() throws Exception
   {

      setInitialVaulConditions("src/test/resources/keystore/vault.jks", "target/vaults/vault2/vault.jks",
            "src/test/resources/keystore/vault_data", "target/vaults/vault2/vault_data");

      Map<String,Object> options = getVaultOptionsMap(
            "target/vaults/vault2/vault.jks",
            "target/vaults/vault2/vault_data",
            "vault", "12438567", 50, "{CLASS}org.jboss.test.security.vault.KeystorePasswordProvider");

      String vaultBlock = "aBlock";
      String attributeName = "anAttribute";

      char[] attributeValue = "aValue".toCharArray();

      SecurityVault vault = getNewSecurityVaultInstance();

      vault.init(options);
      assertTrue(vault.isInitialized());

      Map<String,Object> handshakeOptions = new HashMap<String,Object>();

      byte[] sharedKey = vault.handshake(handshakeOptions);
      assertNotNull(sharedKey);

      vault.store(vaultBlock, attributeName, attributeValue , sharedKey);

      assertTrue(vault.exists(vaultBlock, attributeName));
      //Now retrieve
      assertEquals(new String(attributeValue), new String(vault.retrieve(vaultBlock, attributeName, sharedKey)));

      vault.store(vaultBlock+"1", attributeName+"2", attributeValue, sharedKey);
      assertEquals(new String(attributeValue), new String(vault.retrieve(vaultBlock+"1", attributeName+"2", sharedKey)));

      System.out.println("Currently storing:" + vault.keyList());

      assertTrue(vault.remove(vaultBlock+"1", attributeName+"2", sharedKey));
      assertFalse(vault.exists(vaultBlock+"1", attributeName+"2"));
   }

   @Test
   public void testExtCmdBasedKeystorePassword() throws Exception
   {
      // since this test uses an external BASH script it is valid for Linux systems only
      String OS_NAME = SecurityActions.getProperty("os.name", null);
      Assume.assumeTrue(OS_NAME.startsWith("Linux") || OS_NAME.startsWith("LINUX"));

      setInitialVaulConditions("src/test/resources/keystore/vault.jks", "target/vaults/vault2/vault.jks",
            "src/test/resources/keystore/vault_data", "target/vaults/vault2/vault_data");

      String absolutePathToAskPass = SecurityVaultUnitTestCase.class.getResource("/bin/askpass.sh").getFile();
      System.out.println("absolutePathToAskPass: " + absolutePathToAskPass);

      // 'Enter passphrase for *' is hard-coded into kwalletaskpass for example
      Map<String,Object> options = getVaultOptionsMap(
            "target/vaults/vault2/vault.jks",
            "target/vaults/vault2/vault_data",
            "vault", "12438567", 50, "{CMD}/bin/sh," + absolutePathToAskPass + ",Enter passphrase for askpass test");

      String vaultBlock = "aBlock";
      String attributeName = "anAttribute";

      char[] attributeValue = "aValue".toCharArray();

      SecurityVault vault = getNewSecurityVaultInstance();

      vault.init(options);
      assertTrue(vault.isInitialized());

      Map<String,Object> handshakeOptions = new HashMap<String,Object>();

      byte[] sharedKey = vault.handshake(handshakeOptions);
      assertNotNull(sharedKey);

      vault.store(vaultBlock, attributeName, attributeValue , sharedKey);

      assertTrue(vault.exists(vaultBlock, attributeName));
      //Now retrieve
      assertEquals(new String(attributeValue), new String(vault.retrieve(vaultBlock, attributeName, sharedKey)));

      vault.store(vaultBlock+"1", attributeName+"2", attributeValue, sharedKey);
      assertEquals(new String(attributeValue), new String(vault.retrieve(vaultBlock+"1", attributeName+"2", sharedKey)));

      System.out.println("Currently storing:" + vault.keyList());

      assertTrue(vault.remove(vaultBlock+"1", attributeName+"2", sharedKey));
      assertFalse(vault.exists(vaultBlock+"1", attributeName+"2"));
   }

   /**
    * See src/test/resources/vault-v0/readme.txt for initial vault setup (including secured attributes).
    * @throws Exception
    */
   @Test
   public void testConversion() throws Exception {

      setInitialVaulConditions("src/test/resources/vault-v0/vault-jks.keystore", "target/vaults/vault-v0/vault-jks.keystore", 
            "src/test/resources/vault-v0/vault_data", "target/vaults/vault-v0/vault_data");
      
      final Map<String, Object> options = getVaultOptionsMap(
            "target/vaults/vault-v0/vault-jks.keystore", 
            "target/vaults/vault-v0/vault_data", 
            "thealias", "24681359", 88, "secretsecret");
      
      SecurityVault vault = getNewSecurityVaultInstance(); 

      // init should do the automatic conversion
      vault.init(options);
      assertTrue(vault.isInitialized());
      
      byte[] sharedKey = vault.handshake(null);
      assertNotNull(sharedKey);
      
      // let's try to check if the converted vault contains all secret attributes from initial vault
      assertSecretValue(vault, "vb", "attr1", "pwd1");
      assertSecretValue(vault, "vb", "attr2", "pwd2");
      assertSecretValue(vault, "vb1", "attr1", "pwd3");
      assertSecretValue(vault, "vb2", "attr2", "pwd4");
      assertSecretValue(vault, "vb2", "attr3", "pwd5");
      assertSecretValue(vault, "vb", "attr3", "pwd6");
      
      
      // get new instance of vault to simulate restart of application server 
      SecurityVault convertedVault = getNewSecurityVaultInstance();
      assertFalse(convertedVault.isInitialized());
      convertedVault.init(options);
      assertTrue(convertedVault.isInitialized());

      convertedVault.handshake(null);
      
      // now try the same attributes on converted vault after restart
      assertSecretValue(convertedVault, "vb", "attr1", "pwd1");
      assertSecretValue(convertedVault, "vb", "attr2", "pwd2");
      assertSecretValue(convertedVault, "vb1", "attr1", "pwd3");
      assertSecretValue(convertedVault, "vb2", "attr2", "pwd4");
      assertSecretValue(convertedVault, "vb2", "attr3", "pwd5");
      assertSecretValue(convertedVault, "vb", "attr3", "pwd6");
      
   }
   
   @Test
   public void testVault_V1_open_retrieve() throws Exception {

      setInitialVaulConditions("src/test/resources/vault-v1/vault-jceks.keystore", "target/vaults/vault-v1/vault-jceks.keystore", 
            "src/test/resources/vault-v1/vault_data", "target/vaults/vault-v1/vault_data");
      
      final Map<String, Object> options = getVaultOptionsMap(
            "target/vaults/vault-v1/vault-jceks.keystore", 
            "target/vaults/vault-v1/vault_data", 
            "test", "12345678", 34, "secretsecret");
      
      SecurityVault vault = getNewSecurityVaultInstance();
      assertFalse(vault.isInitialized());
      
      vault.init(options);
      assertTrue(vault.isInitialized());
      
      vault.handshake(null);
      
      // let's try to check if proper values are stored in the vault
      assertSecretValue(vault, "vb1", "attr11", "secret11");
      assertSecretValue(vault, "vb1", "attr12", "secret12");
      
   }

   @Test(expected = SecurityVaultException.class)
   public void testVault_V1_open_wrong_alias() throws Exception {

      setInitialVaulConditions("src/test/resources/vault-v1/vault-jceks.keystore", "target/vaults/vault-v1-wrong/vault-jceks.keystore", 
            "src/test/resources/vault-v1/vault_data", "target/vaults/vault-v1-wrong/vault_data");
      
      final Map<String, Object> options = getVaultOptionsMap(
            "target/vaults/vault-v1-wrong/vault-jceks.keystore", 
            "target/vaults/vault-v1-wrong/vault_data", 
            "thewrongalias", "12345678", 34, "secretsecret");
      
      SecurityVault vault = getNewSecurityVaultInstance();
      assertFalse(vault.isInitialized());
      
      vault.init(options);
      
   }

   @Test(expected = SecurityVaultException.class)
   public void testVaultWithReplacedKeystore() throws Exception {

      setInitialVaulConditions("src/test/resources/vault-v1/vault-replacement-jceks.keystore", "target/vaults/vault-v1/vault-jceks.keystore", 
            "src/test/resources/vault-v1/vault_data", "target/vaults/vault-v1/vault_data");
      
      final Map<String, Object> options = getVaultOptionsMap(
            "target/vaults/vault-v1/vault-jceks.keystore", 
            "target/vaults/vault-v1/vault_data", 
            "test", "12345678", 34, "secretsecret");
      
      SecurityVault vault = getNewSecurityVaultInstance();
      assertFalse(vault.isInitialized());
      
      vault.init(options);
      assertTrue(vault.isInitialized());
      
      vault.handshake(null);
      
      // let's try to check if the converted vault contains all secret attributes from initial vault
      assertSecretValue(vault, "vb1", "attr11", "secret11");
      assertSecretValue(vault, "vb1", "attr12", "secret12");
      
   }
   
   @Test
   public void testMoreSecretKeys() throws Exception {
      setInitialVaulConditions("src/test/resources/vault-v1-more/vault-jceks.keystore", "target/vaults/vault-v1-more/vault-jceks.keystore", 
            "src/test/resources/vault-v1-more/vault_data", "target/vaults/vault-v1-more/vault_data");
      
      final Map<String, Object> options = getVaultOptionsMap(
            "target/vaults/vault-v1-more/vault-jceks.keystore", 
            "target/vaults/vault-v1-more/vault_data", 
            "test", "12345678", 34, "secretsecret");
      
      SecurityVault vault = getNewSecurityVaultInstance();
      assertFalse(vault.isInitialized());
      
      vault.init(options);
      assertTrue(vault.isInitialized());
      
      vault.handshake(null);
      
      // let's try to check if proper values are stored in the vault
      assertSecretValue(vault, "vb1", "attr11", "secret11");
      assertSecretValue(vault, "vb1", "attr12", "secret12");
      
      final Map<String, Object> options2 = getVaultOptionsMap(
            "target/vaults/vault-v1-more/vault-jceks.keystore", 
            "target/vaults/vault-v1-more/vault_data", 
            "test2", "12345678", 34, "secretsecret");
      
      SecurityVault vault2 = getNewSecurityVaultInstance();
      assertFalse(vault2.isInitialized());
      
      vault2.init(options2);
      assertTrue(vault2.isInitialized());
      
      vault2.handshake(null);
      
      // let's try to check different alias can retrieve proper attribute
      assertSecretValue(vault2, "vb1", "attr13", "secret13");

      try {
         assertSecretValue(vault2, "vb1", "attr11", "secret11");
         fail("retrieving security attribute with different secret key alias has to fail.");
      }
      catch (SecurityVaultException e) {
         // deliberately empty
      }
      catch (Throwable e) {
         fail("unexpected exception " + e.getStackTrace().toString());
      }
      
      
   }
   
   @Test
   public void testUtil() throws Exception
   {
	   assertFalse(SecurityVaultUtil.isVaultFormat((String)null));
	   assertFalse(SecurityVaultUtil.isVaultFormat((char[])null));
   }
   
   private String getMaskedPassword(String pwd, String salt, int iterationCount) throws Exception
   {
      if (Util.isPasswordCommand(pwd))
         return pwd;

      String algo = "PBEwithMD5andDES";
      
      // Create the PBE secret key 
      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEwithMD5andDES");

      char[] password = "somearbitrarycrazystringthatdoesnotmatter".toCharArray();
      PBEParameterSpec cipherSpec = new PBEParameterSpec(salt.getBytes(), iterationCount);
      PBEKeySpec keySpec = new PBEKeySpec(password);
      SecretKey cipherKey = factory.generateSecret(keySpec);
      
      String maskedPass = PBEUtils.encode64(pwd.getBytes(), algo, cipherKey, cipherSpec);
      
      return PicketBoxSecurityVault.PASS_MASK_PREFIX + maskedPass;
   }
   

   private Map<String, Object> getVaultOptionsMap(String keystore, String encDataDir, String alias, String salz, int iter,
         String password) throws Exception {
      Map<String, Object> options = new HashMap<String, Object>();
      options.put(PicketBoxSecurityVault.KEYSTORE_URL, keystore);
      options.put(PicketBoxSecurityVault.KEYSTORE_PASSWORD, getMaskedPassword(password, salz, iter));
      options.put(PicketBoxSecurityVault.KEYSTORE_ALIAS, alias);
      options.put(PicketBoxSecurityVault.SALT, salz);
      options.put(PicketBoxSecurityVault.ITERATION_COUNT, String.valueOf(iter));
      options.put(PicketBoxSecurityVault.ENC_FILE_DIR, encDataDir);
      return options;
   }
   
   public static void setInitialVaulConditions(String originalKeyStoreFile, String targetKeyStoreFile,
         String originalVaultContentDir, String targetVaultContentDir) throws Exception {

      File tKS = new File(targetKeyStoreFile);
      File parent = tKS.getParentFile();
      if (!parent.exists()) {
         parent.mkdirs();
      }
      SecurityVaultUnitTestCase.copyFile(new File(originalKeyStoreFile), tKS);

      File targetVaultContent = new File(targetVaultContentDir);
      cleanDirectory(targetVaultContent);
      File originVault = new File(originalVaultContentDir);
      for (File f : originVault.listFiles()) {
         if (f.isFile()) // some version control systems add a hidden directory, we must make sure we won't copy those.
           SecurityVaultUnitTestCase.copyFile(f, new File(targetVaultContent.getAbsolutePath() + File.separator + f.getName()));
      }
   }

    /**
     * Make clean new directory.
     * 
     * @param directory
     */
    public static void cleanDirectory(File directory) {
       if (directory.exists()) {
           for (File f: directory.listFiles()) { f.delete(); }
           directory.delete();
       }
       directory.mkdirs();
    }
    
    /**
     * Copy file method.
     * 
     * @param sourceFile
     * @param destFile
     * @throws IOException
     */
     public static void copyFile(File sourceFile, File destFile) throws IOException {
         if (!destFile.exists()) {
             destFile.createNewFile();
         }
         FileInputStream fIn = null;
         FileOutputStream fOut = null;
         FileChannel source = null;
         FileChannel destination = null;
         try {
             fIn = new FileInputStream(sourceFile);
             source = fIn.getChannel();
             fOut = new FileOutputStream(destFile);
             destination = fOut.getChannel();
             long transfered = 0;
             long bytes = source.size();
             while (transfered < bytes) {
                 transfered += destination.transferFrom(source, 0, source.size());
                 destination.position(transfered);
             }
         } finally {
             if (source != null) {
                 source.close();
             } else if (fIn != null) {
                 fIn.close();
             }
             if (destination != null) {
                 destination.close();
             } else if (fOut != null) {
                 fOut.close();
             }
         }
     }

   static Class<?> loadClass(final Class<?> clazz, final String fqn) {
      return AccessController.doPrivileged(new PrivilegedAction<Class<?>>() {
         public Class<?> run() {
            ClassLoader cl = clazz.getClassLoader();
            Class<?> loadedClass = null;
            try {
               loadedClass = cl.loadClass(fqn);
            } catch (ClassNotFoundException e) {
            }
            return loadedClass;
         }
      });

     }

   private void assertSecretValue(SecurityVault vault, String vaultBlock, String attributeName, String expectedSecuredAttributeValue) throws SecurityVaultException {
      assertEquals("Expected value has to match the one in vault. " + vaultBlock + ":" + attributeName + "=" + expectedSecuredAttributeValue,
            new String(expectedSecuredAttributeValue), 
            new String(vault.retrieve(vaultBlock, attributeName, null))); 
   }
   
   /**
    * get new instance of vault to simulate restart of application server
    * @return
    * @throws Exception
    */
   private SecurityVault getNewSecurityVaultInstance() throws Exception {
      Class<?> vaultClass = loadClass(SecurityVaultFactory.class, "org.picketbox.plugins.vault.PicketBoxSecurityVault");
      return (SecurityVault)vaultClass.newInstance();
   }
    
}