/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
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

package org.jboss.security;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Key;
import java.security.KeyStore;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;

import org.jboss.logging.Logger;
import org.jboss.security.plugins.SecurityKeyManager;

/**
 * A security domain used to configure SSL.
 *
 * @author <a href="mailto:mmoyses@redhat.com">Marcus Moyses</a>
 */
public class JBossJSSESecurityDomain implements JSSESecurityDomain
{

   private static Logger log = Logger.getLogger(JBossJSSESecurityDomain.class);

   private KeyStore keyStore;

   private KeyManagerFactory keyManagerFactory;
   
   private KeyManager[] keyManagers;

   private String keyStoreType = "JKS";

   private URL keyStoreURL;

   private char[] keyStorePassword;

   private String keyStoreProvider;
   
   private String keyStoreProviderArgument;

   private String keyManagerFactoryProvider;

   private String keyManagerFactoryAlgorithm;

   private KeyStore trustStore;

   private TrustManagerFactory trustManagerFactory;
   
   private TrustManager[] trustManagers;

   private String trustStoreType = "JKS";

   private URL trustStoreURL;

   private char[] trustStorePassword;

   private String trustStoreProvider;
   
   private String trustStoreProviderArgument;

   private String trustManagerFactoryProvider;

   private String trustManagerFactoryAlgorithm;

   private String clientAlias;
   
   private String serverAlias;

   private boolean clientAuth;

   private char[] serviceAuthToken;
   
   private String[] cipherSuites;
   
   private String[] protocols;

   private String name;

   public JBossJSSESecurityDomain(String securityDomainName)
   {
      this.name = securityDomainName;
   }

   public String getKeyStoreType()
   {
      return keyStoreType;
   }

   public void setKeyStoreType(String keyStoreType)
   {
      this.keyStoreType = keyStoreType;
   }

   public String getKeyStoreURL()
   {
      String url = null;
      if (keyStoreURL != null)
         url = keyStoreURL.toExternalForm();
      return url;
   }

   public void setKeyStoreURL(String keyStoreURL) throws IOException
   {
      this.keyStoreURL = validateStoreURL(keyStoreURL);
   }

   public String getKeyStoreProvider()
   {
      return keyStoreProvider;
   }

   public void setKeyStoreProvider(String keyStoreProvider)
   {
      this.keyStoreProvider = keyStoreProvider;
   }

   public String getKeyManagerFactoryProvider()
   {
      return keyManagerFactoryProvider;
   }
   
   public String getKeyStoreProviderArgument()
   {
      return keyStoreProviderArgument;
   }

   public void setKeyStoreProviderArgument(String keyStoreProviderArgument)
   {
      this.keyStoreProviderArgument = keyStoreProviderArgument;
   }

   public void setKeyManagerFactoryProvider(String keyManagerFactoryProvider)
   {
      this.keyManagerFactoryProvider = keyManagerFactoryProvider;
   }

   public String getKeyManagerFactoryAlgorithm()
   {
      return keyManagerFactoryAlgorithm;
   }

   public void setKeyManagerFactoryAlgorithm(String keyManagerFactoryAlgorithm)
   {
      this.keyManagerFactoryAlgorithm = keyManagerFactoryAlgorithm;
   }

   public String getTrustStoreType()
   {
      return trustStoreType;
   }

   public void setTrustStoreType(String trustStoreType)
   {
      this.trustStoreType = trustStoreType;
   }

   public String getTrustStoreURL()
   {
      String url = null;
      if (trustStoreURL != null)
         url = trustStoreURL.toExternalForm();
      return url;
   }

   public void setTrustStoreURL(String trustStoreURL) throws IOException
   {
      this.trustStoreURL = validateStoreURL(trustStoreURL);
   }

   public String getTrustStoreProvider()
   {
      return trustStoreProvider;
   }

   public void setTrustStoreProvider(String trustStoreProvider)
   {
      this.trustStoreProvider = trustStoreProvider;
   }
   
   public String getTrustStoreProviderArgument()
   {
      return trustStoreProviderArgument;
   }

   public void setTrustStoreProviderArgument(String trustStoreProviderArgument)
   {
      this.trustStoreProviderArgument = trustStoreProviderArgument;
   }

   public String getTrustManagerFactoryProvider()
   {
      return trustManagerFactoryProvider;
   }

   public void setTrustManagerFactoryProvider(String trustManagerFactoryProvider)
   {
      this.trustManagerFactoryProvider = trustManagerFactoryProvider;
   }

   public String getTrustManagerFactoryAlgorithm()
   {
      return trustManagerFactoryAlgorithm;
   }

   public void setTrustManagerFactoryAlgorithm(String trustManagerFactoryAlgorithm)
   {
      this.trustManagerFactoryAlgorithm = trustManagerFactoryAlgorithm;
   }

   @Override
   public String getClientAlias()
   {
      return clientAlias;
   }

   public void setClientAlias(String clientAlias)
   {
      this.clientAlias = clientAlias;
   }

   @Override
   public String getServerAlias()
   {
      return serverAlias;
   }

   public void setServerAlias(String serverAlias)
   {
      this.serverAlias = serverAlias;
   }

   @Override
   public boolean isClientAuth()
   {
      return clientAuth;
   }

   public void setClientAuth(boolean clientAuth)
   {
      this.clientAuth = clientAuth;
   }

   @Override
   public KeyStore getKeyStore()
   {
      return keyStore;
   }

   @Override
   public KeyStore getTrustStore()
   {
      return trustStore;
   }

   public void setKeyStorePassword(String keyStorePassword) throws Exception
   {
      this.keyStorePassword = Util.loadPassword(keyStorePassword);
   }

   public void setTrustStorePassword(String trustStorePassword) throws Exception
   {
      this.trustStorePassword = Util.loadPassword(trustStorePassword);
   }

   public void setServiceAuthToken(String serviceAuthToken) throws Exception
   {
      this.serviceAuthToken = Util.loadPassword(serviceAuthToken);
   }

   @Override
   public KeyManager[] getKeyManagers() throws SecurityException
   {
      return keyManagers;
   }

   @Override
   public TrustManager[] getTrustManagers() throws SecurityException
   {
      return trustManagers;
   }

   @Override
   public String getSecurityDomain()
   {
      return name;
   }

   @Override
   public Key getKey(String alias, String serviceAuthToken) throws Exception
   {
      log.debug(this + " got request for key with alias '" + alias + "'");

      Key key = keyStore.getKey(alias, keyStorePassword);

      if (key == null || key instanceof PublicKey)
      {
         return key;
      }

      verifyServiceAuthToken(serviceAuthToken);

      return key;
   }

   @Override
   public Certificate getCertificate(String alias) throws Exception
   {
      log.debug(this + " got request for certifcate with alias '" + alias + "'");

      return trustStore.getCertificate(alias);
   }

   @Override
   public void reloadKeyAndTrustStore() throws Exception
   {
      loadKeyAndTrustStore();
   }
   
   @Override
   public String[] getCipherSuites()
   {
      return cipherSuites;
   }
   
   public void setCipherSuites(String cipherSuites)
   {
      String[] cs = cipherSuites.split(",");
      this.cipherSuites = cs;
   }

   @Override
   public String[] getProtocols()
   {
      return protocols;
   }
   
   public void setProtocols(String protocols)
   {
      String[] p = protocols.split(",");
      this.protocols = p;
   }

   private URL validateStoreURL(String storeURL) throws IOException
   {
      URL url = null;
      // First see if this is a URL
      try
      {
         url = new URL(storeURL);
      }
      catch (MalformedURLException e)
      {
         // Not a URL or a protocol without a handler
      }

      // Next try to locate this as file path
      if (url == null)
      {
         File tst = new File(storeURL);
         if (tst.exists() == true)
            url = tst.toURI().toURL();
      }

      // Last try to locate this as a classpath resource
      if (url == null)
      {
         ClassLoader loader = SecurityActions.getContextClassLoader();
         url = loader.getResource(storeURL);
      }

      // Fail if no valid key store was located
      if (url == null)
      {
         String msg = "Failed to find url=" + storeURL + " as a URL, file or resource";
         throw new MalformedURLException(msg);
      }
      return url;
   }

   private void verifyServiceAuthToken(String serviceAuthToken) throws SecurityException
   {
      if (this.serviceAuthToken == null)
      {
         throw new IllegalStateException(
               getSecurityDomain()
                     + " has been requested to provide sensitive security information, but no service authentication token has been configured on it. Use setServiceAuthToken().");
      }

      boolean verificationSuccessful = true;
      char[] ca = serviceAuthToken.toCharArray();

      if (this.serviceAuthToken.length == ca.length)
      {
         for (int i = 0; i < this.serviceAuthToken.length; i++)
         {
            if (this.serviceAuthToken[i] != ca[i])
            {
               verificationSuccessful = false;
               break;
            }
         }

         if (verificationSuccessful)
         {
            log.debug("valid service authentication token");
            return;
         }
      }

      throw new SecurityException("service authentication token verification failed");
   }

   private void loadKeyAndTrustStore() throws Exception
   {
      if (keyStorePassword != null)
      {
         if (keyStoreProvider != null)
         {
            if (keyStoreProviderArgument != null)
            {
               ClassLoader loader = SecurityActions.getContextClassLoader();
               Class clazz = loader.loadClass(keyStoreProvider);
               Class[] ctorSig = {String.class};
               Constructor ctor = clazz.getConstructor(ctorSig);
               Object[] ctorArgs = {keyStoreProviderArgument};
               Provider provider = (Provider) ctor.newInstance(ctorArgs);
               keyStore = KeyStore.getInstance(keyStoreType, provider);
            }
            else
               keyStore = KeyStore.getInstance(keyStoreType, keyStoreProvider);
         }
         else
            keyStore = KeyStore.getInstance(keyStoreType);
         InputStream is = null;
         if ((!"PKCS11".equalsIgnoreCase(keyStoreType) || !"PKCS11IMPLKS".equalsIgnoreCase(keyStoreType))
               && keyStoreURL != null)
         {
            is = keyStoreURL.openStream();
         }
         keyStore.load(is, keyStorePassword);
         String algorithm = null;
         if (keyManagerFactoryAlgorithm != null)
            algorithm = keyManagerFactoryAlgorithm;
         else
            algorithm = KeyManagerFactory.getDefaultAlgorithm();
         if (keyManagerFactoryProvider != null)
            keyManagerFactory = KeyManagerFactory.getInstance(algorithm, keyManagerFactoryProvider);
         else
            keyManagerFactory = KeyManagerFactory.getInstance(algorithm);
         keyManagerFactory.init(keyStore, keyStorePassword);
         keyManagers = keyManagerFactory.getKeyManagers();
         for (int i = 0; i < keyManagers.length; i++)
         {
            keyManagers[i] = new SecurityKeyManager((X509KeyManager) keyManagers[i], serverAlias, clientAlias);
         }
      }
      if (trustStorePassword != null)
      {
         if (trustStoreProvider != null)
         {
            if (trustStoreProviderArgument != null)
            {
               ClassLoader loader = Thread.currentThread().getContextClassLoader();
               Class clazz = loader.loadClass(trustStoreProvider);
               Class[] ctorSig = {String.class};
               Constructor ctor = clazz.getConstructor(ctorSig);
               Object[] ctorArgs = {trustStoreProviderArgument};
               Provider provider = (Provider) ctor.newInstance(ctorArgs);
               trustStore = KeyStore.getInstance(trustStoreType, provider);
            }
            else
               trustStore = KeyStore.getInstance(trustStoreType, trustStoreProvider);
         }
         else
            trustStore = KeyStore.getInstance(trustStoreType);
         InputStream is = null;
         if ((!"PKCS11".equalsIgnoreCase(trustStoreType) || !"PKCS11IMPLKS".equalsIgnoreCase(trustStoreType))
               && trustStoreURL != null)
         {
            is = trustStoreURL.openStream();
         }
         trustStore.load(is, trustStorePassword);
         String algorithm = null;
         if (trustManagerFactoryAlgorithm != null)
            algorithm = trustManagerFactoryAlgorithm;
         else
            algorithm = TrustManagerFactory.getDefaultAlgorithm();
         if (trustManagerFactoryProvider != null)
            trustManagerFactory = TrustManagerFactory.getInstance(algorithm, trustStoreProvider);
         else
            trustManagerFactory = TrustManagerFactory.getInstance(algorithm);
         trustManagerFactory.init(trustStore);
         trustManagers = trustManagerFactory.getTrustManagers();
      }
      else if (keyStore != null)
      {
         trustStore = keyStore;
         String algorithm = null;
         if (trustManagerFactoryAlgorithm != null)
            algorithm = trustManagerFactoryAlgorithm;
         else
            algorithm = TrustManagerFactory.getDefaultAlgorithm();
         trustManagerFactory = TrustManagerFactory.getInstance(algorithm);
         trustManagerFactory.init(trustStore);
         trustManagers = trustManagerFactory.getTrustManagers();
      }
   }

}
