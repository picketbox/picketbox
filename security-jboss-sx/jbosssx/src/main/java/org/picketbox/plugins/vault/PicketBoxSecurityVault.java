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
package org.picketbox.plugins.vault;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.jboss.logging.Logger;
import org.jboss.security.ErrorCodes;
import org.jboss.security.plugins.PBEUtils;
import org.jboss.security.vault.SecurityVault;
import org.jboss.security.vault.SecurityVaultException;
import org.picketbox.commons.cipher.Base64;
import org.picketbox.util.EncryptionUtil;
import org.picketbox.util.KeyStoreUtil;
import org.picketbox.util.StringUtil;

/**
 * An instance of {@link SecurityVault} that uses
 * a {@link KeyStore} 
 * The shared key just uses a concatenation of a {@link java.uti.UUID}
 * and a keystore alias.
 * 
 * The following options are expected in the {@link SecurityVault#init(Map)} call:
 * ENC_FILE_DIR: the location where the encoded files will be kept. End with "/" or "\" based on your platform
 * KEYSTORE_URL: location where your keystore is located
 * KEYSTORE_PASSWORD: Masked keystore password.  Has to be prepended with MASK-
 * KEYSTORE_ALIAS: Alias where the keypair is located
 * SALT: salt of the masked password. Ensured it is 8 characters in length
 * ITERATION_COUNT: Iteration Count of the masked password.
 * KEY_SIZE: Key size of encryption. Default is 128 bytes.
 * 
 * @author Anil.Saldhana@redhat.com
 * @since Aug 12, 2011
 */
public class PicketBoxSecurityVault implements SecurityVault
{
   protected static Logger log = Logger.getLogger(PicketBoxSecurityVault.class);
   
   protected boolean finishedInit = false;

   protected KeyStore keystore = null;
   
   private KeyPair keypair = null;
   
   protected String encryptionAlgorithm = "AES";
   
   protected int keySize = 128;
   
   private char[] keyStorePWD = null;
   
   protected Map<String,byte[]> theContent= new ConcurrentHashMap<String,byte[]>();
   
   protected Map<String,byte[]> sharedKeyMap = new ConcurrentHashMap<String,byte[]>();
   
   public static final String ENC_FILE_DIR = "ENC_FILE_DIR";
   
   public static final String KEYSTORE_URL = "KEYSTORE_URL";
   
   public static final String KEYSTORE_PASSWORD = "KEYSTORE_PASSWORD";
   
   public static final String KEYSTORE_ALIAS = "KEYSTORE_ALIAS";
   
   public static final String SALT = "SALT";
   
   public static final String ITERATION_COUNT = "ITERATION_COUNT";
   
   public static final String PASS_MASK_PREFIX = "MASK-";
   
   public static final String PUBLIC_CERT = "PUBLIC_CERT";
   
   public static final String KEY_SIZE = "KEY_SIZE"; 

   protected static final String ENCODED_FILE = "ENC.dat";
   protected static final String SHARED_KEY_FILE = "Shared.dat";
   protected static final String ADMIN_KEY = "ADMIN_KEY";
   
   protected String decodedEncFileDir;
   
   protected String LINE_BREAK = "LINE_BREAK";
   
   /*
    * @see org.jboss.security.vault.SecurityVault#init(java.util.Map)
    */
   @SuppressWarnings("unchecked")
   public void init(Map<String, Object> options) throws SecurityVaultException
   {
      if(options == null)
         throw new SecurityVaultException(ErrorCodes.NULL_ARGUMENT + "Options is null");
      
      if(options.isEmpty())
         throw new SecurityVaultException(ErrorCodes.NULL_VALUE + "Options is empty");
      
      String keystoreURL = (String) options.get(KEYSTORE_URL);
      if(keystoreURL == null)
         throw new SecurityVaultException(ErrorCodes.NULL_VALUE + "Null " + KEYSTORE_URL);
      keystoreURL = StringUtil.getSystemPropertyAsString(keystoreURL);
      
      String maskedPassword = (String) options.get(KEYSTORE_PASSWORD);
      if(maskedPassword == null)
         throw new SecurityVaultException(ErrorCodes.NULL_VALUE + "Null masked keystore password");
      if(maskedPassword.startsWith(PASS_MASK_PREFIX) == false)
         throw new SecurityVaultException(ErrorCodes.NULL_VALUE + "Keystore password is not masked");
   
      String salt = (String) options.get(SALT);
      if(salt == null)
         throw new SecurityVaultException(ErrorCodes.NULL_VALUE + "Salt is null");
      
      String iterationCountStr = (String) options.get(ITERATION_COUNT);
      if(iterationCountStr == null)
         throw new SecurityVaultException(ErrorCodes.NULL_VALUE + "Iteration Count is not set");
      int iterationCount = Integer.parseInt(iterationCountStr);
      
      String alias = (String) options.get(KEYSTORE_ALIAS);
      if(alias == null)
         throw new SecurityVaultException(ErrorCodes.NULL_VALUE + "Keystore Alias is null");
      
      String keySizeStr = (String) options.get(KEY_SIZE);
      if(keySizeStr != null)
      {
         keySize = Integer.parseInt(keySizeStr);
      }
      
      String encFileDir = (String) options.get(ENC_FILE_DIR);
      if(encFileDir == null)
         throw new SecurityVaultException(ErrorCodes.NULL_VALUE + "Option ENC_FILE_DIR is missing");

      try
      {
         decodedEncFileDir = StringUtil.getSystemPropertyAsString(encFileDir);
         if(directoryExists(decodedEncFileDir) == false)
            throw new SecurityVaultException(ErrorCodes.PROCESSING_FAILED + decodedEncFileDir + " does not exist");
         
         if(!(decodedEncFileDir.endsWith("/") || decodedEncFileDir.endsWith("\\")))
         {
            throw new SecurityVaultException(ErrorCodes.WRONG_FORMAT + decodedEncFileDir + "does not end with / or \\");
         }
         if(encodedFileExists(decodedEncFileDir) ==false)
         {
            setUpVault(decodedEncFileDir);
         }
         
         FileInputStream fis = new FileInputStream(decodedEncFileDir + ENCODED_FILE);
         ObjectInputStream ois = new ObjectInputStream(fis);
         theContent = (Map<String, byte[]>) ois.readObject();

         FileInputStream mapFile = new FileInputStream(decodedEncFileDir + SHARED_KEY_FILE );
         ObjectInputStream mapIS = new ObjectInputStream(mapFile);
         
         sharedKeyMap = (Map<String, byte[]>) mapIS.readObject();
      }
      catch (Exception e)
      { 
         throw new SecurityVaultException(e); 
      }

      try
      {
         String keystorePass = decode(maskedPassword, salt, iterationCount);
         keyStorePWD = keystorePass.toCharArray();
         keystore = KeyStoreUtil.getKeyStore(keystoreURL, keystorePass.toCharArray()); 
         keypair = KeyStoreUtil.getPrivateKey(keystore, alias, keystorePass.toCharArray());
      }
      catch (Exception e)
      { 
         throw new SecurityVaultException(ErrorCodes.PROCESSING_FAILED + "Unable to get Keystore:",e);
      }
      finishedInit = true;
   }

   /*
    * @see org.jboss.security.vault.SecurityVault#isInitialized()
    */
   public boolean isInitialized()
   {
      return finishedInit;
   }

   /*
    * @see org.jboss.security.vault.SecurityVault#handshake(java.util.Map)
    */
   public byte[] handshake(Map<String, Object> handshakeOptions) throws SecurityVaultException
   {
      if(handshakeOptions == null)
         throw new SecurityVaultException(ErrorCodes.NULL_ARGUMENT + "Options is null");
      
      if(handshakeOptions.isEmpty())
         throw new SecurityVaultException(ErrorCodes.NULL_VALUE + "Options is empty");
      
      String publicCert = (String) handshakeOptions.get(PUBLIC_CERT);
      if(publicCert == null)
         throw new SecurityVaultException(ErrorCodes.NULL_VALUE + "Public Cert Alias is null");
      
      try
      {
         PublicKey publicKey = KeyStoreUtil.getPublicKey(keystore, publicCert, keyStorePWD);
         if(publicKey == null)
            throw new SecurityVaultException(ErrorCodes.NULL_VALUE + 
            		"Could not retrieve Public Key from KeyStore for alias:" + publicCert);
          
      }
      catch (Exception e)
      {
         throw new SecurityVaultException(e);
      } 
       
      
      StringBuilder uuid = new StringBuilder(UUID.randomUUID().toString());
      uuid.append("LINE_BREAK");
      uuid.append(publicCert);
      
      return Base64.encodeBytes(uuid.toString().getBytes()).getBytes();
   }
   
   /*
    * @see org.jboss.security.vault.SecurityVault#keyList()
    */
   public Set<String> keyList() throws SecurityVaultException
   {
      Set<String> keys = theContent.keySet();
      keys.remove(ADMIN_KEY);
      return keys;
   }

   /*
    * @see org.jboss.security.vault.SecurityVault#store(java.lang.String, java.lang.String, char[], byte[])
    */
   public void store(String vaultBlock, String attributeName, char[] attributeValue, byte[] sharedKey)
         throws SecurityVaultException
   {
      
      if(StringUtil.isNullOrEmpty(vaultBlock))
         throw new SecurityVaultException(ErrorCodes.NULL_VALUE + "vaultBlock is null");
      if(StringUtil.isNullOrEmpty(attributeName))
         throw new SecurityVaultException(ErrorCodes.NULL_VALUE + "attributeName is null");
      
      String mapKey = vaultBlock + "_" + attributeName;
      
      sharedKeyMap.put(mapKey, sharedKey);
      
      String av = new String(attributeValue);
      
      //Get Public Key from shared key
      String decodedSharedKey = new String(Base64.decode(new String(sharedKey)));
      int index = decodedSharedKey.indexOf(LINE_BREAK);
      
      if(index < 0)
         throw new SecurityVaultException(ErrorCodes.MISMATCH_SIZE + "Shared Key is invalid");
      
      String alias = decodedSharedKey.substring(index + LINE_BREAK.length());
      
      Certificate cert;
      try
      {
         cert = keystore.getCertificate(alias);
      }
      catch (KeyStoreException e1)
      { 
         throw new SecurityVaultException(ErrorCodes.PROCESSING_FAILED + "Cannot get certificate:",e1);
      }
      
      EncryptionUtil util = new EncryptionUtil(encryptionAlgorithm,keySize);
      try
      {
         byte[] secretKey = theContent.get(ADMIN_KEY);
         
         SecretKeySpec sKeySpec = new SecretKeySpec(secretKey,encryptionAlgorithm);
         byte[] encryptedData = util.encrypt(av.getBytes(), cert.getPublicKey(), sKeySpec);
         theContent.put(mapKey, encryptedData);
      }
      catch (Exception e1)
      { 
         throw new SecurityVaultException(ErrorCodes.PROCESSING_FAILED + "Unable to encrypt data:",e1);
      }
      try
      {
         writeSharedKeyFile(this.decodedEncFileDir);
      }
      catch (IOException e)
      { 
         throw new SecurityVaultException(ErrorCodes.PROCESSING_FAILED + "Unable to write Shared Key File");
      }
      try
      {
         writeEncodedFile(this.decodedEncFileDir);
      }
      catch (IOException e)
      { 
         throw new SecurityVaultException(ErrorCodes.PROCESSING_FAILED + "Unable to write Encoded File");
      }
   }

   /*
    * @see org.jboss.security.vault.SecurityVault#retrieve(java.lang.String, java.lang.String, byte[])
    */
   public char[] retrieve(String vaultBlock, String attributeName, byte[] sharedKey) throws SecurityVaultException
   {
      if(StringUtil.isNullOrEmpty(vaultBlock))
         throw new SecurityVaultException(ErrorCodes.NULL_ARGUMENT + "vaultBlock is null");
      if(StringUtil.isNullOrEmpty(attributeName))
         throw new SecurityVaultException(ErrorCodes.NULL_ARGUMENT + "attributeName is null");
      
      String mapKey = vaultBlock + "_" + attributeName;
      byte[] encryptedValue = theContent.get(mapKey);
       
      
      byte[] fromMap = sharedKeyMap.get(mapKey);
      
      boolean matches = Arrays.equals(sharedKey, fromMap);
      if(matches == false)
         throw new SecurityVaultException(ErrorCodes.VAULT_MISMATCH + 
        		 "Shared Key does not match for vault block:" + vaultBlock + " and attributeName:" + attributeName);
      
      byte[] secretKey = theContent.get(ADMIN_KEY);
       
      SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, encryptionAlgorithm);
      EncryptionUtil encUtil = new EncryptionUtil(encryptionAlgorithm, keySize);
      try
      {
         return (new String(encUtil.decrypt(encryptedValue, keypair, secretKeySpec))).toCharArray();
      }
      catch (Exception e)
      { 
         throw new SecurityVaultException(ErrorCodes.PROCESSING_FAILED + "Decryption of value failed:",e);
      } 
   }
   /**
    * @see org.jboss.security.vault.SecurityVault#exists(String, String)
    */
   public boolean exists(String vaultBlock, String attributeName) throws SecurityVaultException
   { 
      String mapKey = vaultBlock + "_" + attributeName;
      return theContent.get(mapKey) != null;
   }
   
   /*
    * @see org.jboss.security.vault.SecurityVault#remove(java.lang.String, java.lang.String, byte[])
    */
   public boolean remove(String vaultBlock, String attributeName, byte[] sharedKey)
		   throws SecurityVaultException 
   {
	   String mapKey = vaultBlock + "_" + attributeName;
	   try
	   {
		   theContent.remove(mapKey);
	   }
	   catch(Exception e)
	   {
		   return false;
	   }
	   return true;
	}
   
   private String decode(String maskedString, String salt, int iterationCount) throws Exception
   {
      String pbeAlgo = "PBEwithMD5andDES";
      if (maskedString.startsWith(PASS_MASK_PREFIX))
      {
         // Create the PBE secret key 
         SecretKeyFactory factory = SecretKeyFactory.getInstance(pbeAlgo);

         char[] password = "somearbitrarycrazystringthatdoesnotmatter".toCharArray();
         PBEParameterSpec cipherSpec = new PBEParameterSpec(salt.getBytes(), iterationCount);
         PBEKeySpec keySpec = new PBEKeySpec(password);
         SecretKey cipherKey = factory.generateSecret(keySpec);

         maskedString = maskedString.substring(PASS_MASK_PREFIX.length());
         String decodedValue = PBEUtils.decode64(maskedString, pbeAlgo, cipherKey, cipherSpec);

         maskedString = decodedValue;
      }
      return maskedString;
   }
   
   private void setUpVault(String decodedEncFileDir) throws NoSuchAlgorithmException,IOException
   { 
      theContent = new ConcurrentHashMap<String, byte[]>();
      EncryptionUtil util = new EncryptionUtil(encryptionAlgorithm,keySize);
      SecretKey secretKey = util.generateKey();
      theContent.put(ADMIN_KEY, secretKey.getEncoded()); 
      
      writeEncodedFile(decodedEncFileDir);
      writeSharedKeyFile(decodedEncFileDir);
   }
   
   private void writeEncodedFile(String decodedEncFileDir) throws IOException
   {
      FileOutputStream fos = new FileOutputStream(decodedEncFileDir + ENCODED_FILE);
      ObjectOutputStream oos = new ObjectOutputStream(fos);
      oos.writeObject(theContent);
      oos.close();
   }
   
   private void writeSharedKeyFile(String decodedEncFileDir) throws IOException
   {
      FileOutputStream fos = new FileOutputStream(decodedEncFileDir + SHARED_KEY_FILE);
      ObjectOutputStream oos = new ObjectOutputStream(fos);
      oos.writeObject(sharedKeyMap);
      oos.close(); 
   }
   
   private boolean encodedFileExists(String decodedEncFileDir)
   {
      File file = new File(decodedEncFileDir + ENCODED_FILE);
      return file != null && file.exists();
   }
   
   private boolean directoryExists(String dir)
   {
      File file = new File(dir);
      return file != null && file.exists();
   }
}