/*
 * JBoss, the OpenSource J2EE webOS
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */ 
package org.jboss.security.config;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;

/**
 *  Class that provides the Configuration for authentication,
 *  authorization, mapping info etc
 *  It also holds the information like JSSE keystores, keytypes and
 *  other crypto configuration
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @version $Revision$
 *  @since  Aug 28, 2006
 */
public class SecurityConfiguration
{
   /**
    * Map of Application Policies keyed in by name
    */
   private static HashMap<String,ApplicationPolicy> appPolicies = new HashMap<String,ApplicationPolicy>();
   private static String cipherAlgorithm;
   private static int iterationCount;
   private static String salt;
   private static String keyStoreType;
   private static String keyStoreURL;
   private static String keyStorePass;
   private static String trustStoreType;
   private static String trustStorePass;
   private static String trustStoreURL;
   private static Key cipherKey;
   private static AlgorithmParameterSpec cipherSpec;
   private static boolean deepCopySubjectMode;
   
   /**
    * Add an application policy
    * @param aP Application Policy
    */
   public static void addApplicationPolicy(ApplicationPolicy aP)
   { 
      if(aP == null)
         throw new IllegalArgumentException("application policy is null");
      appPolicies.put(aP.getName(), aP);
   }
   
   /**
    * Remove the Application Policy
    * @param name Name of the Policy
    */
   public static void removeApplicationPolicy(String name)
   {
      appPolicies.remove(name);
   }
   
   /**
    * Get an application policy 
    * @param policyName Name of the Policy (such as "other", "messaging")
    * @return
    */
   public static ApplicationPolicy getApplicationPolicy(String policyName)
   {
      return (ApplicationPolicy)appPolicies.get(policyName);
   } 
   
   public static String getCipherAlgorithm()
   {
      return cipherAlgorithm;
   }
   
   public static void setCipherAlgorithm(String ca)
   {
      cipherAlgorithm = ca;
   }
   
   public static Key getCipherKey()
   {
      return cipherKey;
   }
   
   public static void setCipherKey(Key ca)
   {
      cipherKey = ca;
   }
   
   public static AlgorithmParameterSpec getCipherSpec()
   {
      return cipherSpec;
   }
   
   public static void setCipherSpec(AlgorithmParameterSpec aps)
   {
      cipherSpec = aps;
   }
   
   public static int getIterationCount()
   {
      return iterationCount;
   }

   /** Set the iteration count used with PBE based on the keystore password.
    * @param count - an iteration count randomization value
    */ 
   public static void setIterationCount(int count)
   {
      iterationCount = count;
   }
   
   
   public static String getSalt()
   {
      return salt;
   }
   /** Set the salt used with PBE based on the keystore password.
    * @param salt - an 8 char randomization string
    */ 
   public static void setSalt(String s)
   {
      salt = s;
   }

   
   /** KeyStore implementation type being used.
   @return the KeyStore implementation type being used.
   */
   public static String getKeyStoreType()
   {
      return keyStoreType;
   }
   /** Set the type of KeyStore implementation to use. This is
   passed to the KeyStore.getInstance() factory method.
   */
   public static void setKeyStoreType(String type)
   {
      keyStoreType = type;
   } 
   /** Get the KeyStore database URL string.
   */
   public static String getKeyStoreURL()
   {
      return keyStoreURL;
   }
   /** Set the KeyStore database URL string. This is used to obtain
   an InputStream to initialize the KeyStore.
   */
   public static void setKeyStoreURL(String storeURL)
   {
      keyStoreURL = storeURL;
   }
   
   /** Get the credential string for the KeyStore.
    */
    public static String getKeyStorePass()
    {
       return keyStorePass ;
    }
   
   /** Set the credential string for the KeyStore.
   */
   public static void setKeyStorePass(String password)
   {
      keyStorePass = password;
   }

  /** Get the type of the trust store
   * @return the type of the trust store
   */ 
  public static String getTrustStoreType()
  {
     return trustStoreType;
  }
  
  /** Set the type of the trust store
   * @param type - the trust store implementation type
   */ 
  public static void setTrustStoreType(String type)
  {
     trustStoreType = type;
  }
  
  /** Set the credential string for the trust store.
   */
   public static String getTrustStorePass()
   {
      return trustStorePass;
   }
  
  /** Set the credential string for the trust store.
  */
  public static void setTrustStorePass(String password)
  {
     trustStorePass = password;
  }
  
  /** Get the trust store database URL string.
   */
  public static String getTrustStoreURL()
  {
     return trustStoreURL;
  }
  
  /** Set the trust store database URL string. This is used to obtain
   an InputStream to initialize the trust store.
   */
  public static void setTrustStoreURL(String storeURL)
  {
     trustStoreURL = storeURL;
  }

  public static boolean isDeepCopySubjectMode()
  {
     return deepCopySubjectMode;
  }

  public static void setDeepCopySubjectMode(boolean dcsm)
  {
     deepCopySubjectMode = dcsm;
  }
}