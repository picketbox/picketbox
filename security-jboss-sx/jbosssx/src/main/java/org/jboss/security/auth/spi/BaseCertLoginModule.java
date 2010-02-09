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
package org.jboss.security.auth.spi;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.acl.Group;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Map;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;

import org.jboss.security.SecurityDomain;
import org.jboss.security.auth.callback.ObjectCallback;
import org.jboss.security.auth.certs.X509CertificateVerifier;

/**
 * Base Login Module that uses X509Certificates as credentials for
 * authentication.
 *
 * This login module uses X509Certificates as a
 * credential. It takes the cert as an object and checks to see if the alias in
 * the truststore/keystore contains the same certificate. Subclasses of this
 * module should implement the getRoleSets() method defined by
 * AbstractServerLoginModule. Much of this module was patterned after the
 * UserNamePasswordLoginModule.
 *
 * @author <a href="mailto:jasone@greenrivercomputing.com">Jason Essington</a>
 * @author Scott.Stark@jboss.org
 * @version $Revision$
 */
public class BaseCertLoginModule extends AbstractServerLoginModule
{
   /** A principal derived from the certificate alias */
   private Principal identity;
   /** The client certificate */
   private X509Certificate credential;
   /** The SecurityDomain to obtain the KeyStore/TrustStore from */
   private SecurityDomain domain = null;
   /** An option certificate verifier */
   private X509CertificateVerifier verifier; 

   /** Override the super version to pickup the following options after first
    * calling the super method.
    *
    * option: securityDomain - the name of the SecurityDomain to obtain the
    *    trust and keystore from.
    * option: verifier - the class name of the X509CertificateVerifier to use
    *    for verification of the login certificate
    *
    * @see SecurityDomain
    * @see X509CertificateVerifier
    *
    * @param subject the Subject to update after a successful login.
    * @param callbackHandler the CallbackHandler that will be used to obtain the
    *    the user identity and credentials.
    * @param sharedState a Map shared between all configured login module instances
    * @param options the parameters passed to the login module.
    */
   public void initialize(Subject subject, CallbackHandler callbackHandler,
      Map<String,?> sharedState, Map<String,?> options)
   {
      super.initialize(subject, callbackHandler, sharedState, options);
      trace = log.isTraceEnabled();

      // Get the security domain and default to "other"
      String sd = (String) options.get("securityDomain");
      if (sd == null)
         sd = "java:/jaas/other";

      if( trace )
         log.trace("securityDomain=" + sd);

      try
      {
         Object tempDomain = new InitialContext().lookup(sd);
         if (tempDomain instanceof SecurityDomain)
         {
            domain = (SecurityDomain) tempDomain;
            if( trace )
            {
               if (domain != null)
                  log.trace("found domain: " + domain.getClass().getName());
               else
                  log.trace("the domain " + sd + " is null!");
            }
         }
         else
         {
            log.error("The domain " + sd + " is not a SecurityDomain. All authentication using this module will fail!");
         }
      }
      catch (NamingException e)
      {
         log.error("Unable to find the securityDomain named: " + sd, e);
      }

      String option = (String) options.get("verifier");
      if( option != null )
      {
         try
         {
            ClassLoader loader = SecurityActions.getContextClassLoader();
            Class<?> verifierClass = loader.loadClass(option);
            verifier = (X509CertificateVerifier) verifierClass.newInstance();
         }
         catch(Throwable e)
         {
            if( trace )
               log.trace("Failed to create X509CertificateVerifier", e);
            IllegalArgumentException ex = new IllegalArgumentException("Invalid verifier: "+option);
            ex.initCause(e);
         }
      }

      if( trace )
         log.trace("exit: initialize(Subject, CallbackHandler, Map, Map)");
   }

   /**
    * Perform the authentication of the username and password.
    */
   @SuppressWarnings("unchecked")
   public boolean login() throws LoginException
   {
      if( trace )
         log.trace("enter: login()");
      // See if shared credentials exist
      if (super.login() == true)
      {
         // Setup our view of the user
         Object username = sharedState.get("javax.security.auth.login.name");
         if( username instanceof Principal )
            identity = (Principal) username;
         else
         {
            String name = username.toString();
            try
            {
               identity = createIdentity(name);
            }
            catch(Exception e)
            {
               log.debug("Failed to create principal", e);
               throw new LoginException("Failed to create principal: "+ e.getMessage());
            }
         }

         Object password = sharedState.get("javax.security.auth.login.password");
         if (password instanceof X509Certificate)
            credential = (X509Certificate) password;
         else if (password != null)
         {
            log.debug("javax.security.auth.login.password is not X509Certificate");
            super.loginOk = false;
            return false;
         }
         return true;
      }

      super.loginOk = false;
      Object[] info = getAliasAndCert();
      String alias = (String) info[0];
      credential = (X509Certificate) info[1];

      if (alias == null && credential == null)
      {
         identity = unauthenticatedIdentity;
         super.log.trace("Authenticating as unauthenticatedIdentity=" + identity);
      }

      if (identity == null)
      {
         try
         {
            identity = createIdentity(alias);
         }
         catch(Exception e)
         {
            log.debug("Failed to create identity for alias:"+alias, e);
         }

         if (!validateCredential(alias, credential))
         {
            log.debug("Bad credential for alias=" + alias);
            throw new FailedLoginException("Supplied Credential did not match existing credential for " + alias);
         }
      }

      if (getUseFirstPass() == true)
      {
         // Add authentication info to shared state map
         sharedState.put("javax.security.auth.login.name", alias);
         sharedState.put("javax.security.auth.login.password", credential);
      }
      super.loginOk = true;
      if( trace )
      {
         log.trace("User '" + identity + "' authenticated, loginOk=" + loginOk);
         log.debug("exit: login()");
      }
      return true;
   }

   /** Override to add the X509Certificate to the public credentials
    * @return
    * @throws LoginException
    */
   public boolean commit() throws LoginException
   {
      boolean ok = super.commit();
      if( ok == true )
      {
         // Add the cert to the public credentials
         if (credential != null)
         {
            subject.getPublicCredentials().add(credential);
         }
      }
      return ok;
   }

   /** Subclasses need to override this to provide the roles for authorization
    * @return
    * @throws LoginException
    */
   protected Group[] getRoleSets() throws LoginException
   {
      return new Group[0];
   }

   protected Principal getIdentity()
   {
      return identity;
   }
   protected Object getCredentials()
   {
      return credential;
   }
   protected String getUsername()
   {
      String username = null;
      if (getIdentity() != null)
         username = getIdentity().getName();
      return username;
   }

   protected Object[] getAliasAndCert() throws LoginException
   {
      if( trace )
         log.trace("enter: getAliasAndCert()");
      Object[] info = { null, null };
      // prompt for a username and password
      if (callbackHandler == null)
      {
         throw new LoginException("Error: no CallbackHandler available to collect authentication information");
      }
      NameCallback nc = new NameCallback("Alias: ");
      ObjectCallback oc = new ObjectCallback("Certificate: ");
      Callback[] callbacks = { nc, oc };
      String alias = null;
      X509Certificate cert = null;
      X509Certificate[] certChain;
      try
      {
         callbackHandler.handle(callbacks);
         alias = nc.getName();
         Object tmpCert = oc.getCredential();
         if (tmpCert != null)
         {
            if (tmpCert instanceof X509Certificate)
            {
               cert = (X509Certificate) tmpCert;
               if( trace )
                  log.trace("found cert " + cert.getSerialNumber().toString(16) + ":" + cert.getSubjectDN().getName());
            }
            else if( tmpCert instanceof X509Certificate[] )
            {
               certChain = (X509Certificate[]) tmpCert;
               if( certChain.length > 0 )
                  cert = certChain[0];
            }
            else
            {
               String msg = "Don't know how to obtain X509Certificate from: "
                  +tmpCert.getClass();
               log.warn(msg);
               throw new LoginException(msg);
            }
         }
         else
         {
            log.warn("CallbackHandler did not provide a certificate");
         }
      }
      catch (IOException e)
      {
         log.debug("Failed to invoke callback", e);
         throw new LoginException("Failed to invoke callback: "+e.toString());
      }
      catch (UnsupportedCallbackException uce)
      {
         throw new LoginException("CallbackHandler does not support: "
            + uce.getCallback());
      }

      info[0] = alias;
      info[1] = cert;
      if( trace )
         log.trace("exit: getAliasAndCert()");
      return info;
   }

   protected boolean validateCredential(String alias, X509Certificate cert)
   {
      if( trace )
         log.trace("enter: validateCredentail(String, X509Certificate)");
      boolean isValid = false;

      // if we don't have a trust store, we'll just use the key store.
      KeyStore keyStore = null;
      KeyStore trustStore = null;
      if( domain != null )
      {
         keyStore = domain.getKeyStore();
         trustStore = domain.getTrustStore();
      }
      if( trustStore == null )
         trustStore = keyStore;

      if( verifier != null )
      {
         // Have the verifier validate the cert
         if( trace )
            log.trace("Validating cert using: "+verifier);
         isValid = verifier.verify(cert, alias, keyStore, trustStore);
      }
      else if (keyStore != null && cert != null)
      {
         // Look for the cert in the keystore using the alias
         X509Certificate storeCert = null;
         try
         {
            storeCert = (X509Certificate) keyStore.getCertificate(alias);
            if( trace )
            {
               StringBuffer buf = new StringBuffer("\n\tSupplied Credential: ");
               buf.append(cert.getSerialNumber().toString(16));
               buf.append("\n\t\t");
               buf.append(cert.getSubjectDN().getName());
               buf.append("\n\n\tExisting Credential: ");
               if( storeCert != null )
               {
                  buf.append(storeCert.getSerialNumber().toString(16));
                  buf.append("\n\t\t");
                  buf.append(storeCert.getSubjectDN().getName());
                  buf.append("\n");
               }
               else
               {
                  ArrayList<String> aliases = new ArrayList<String>();
                  Enumeration<String> en = keyStore.aliases();
                  while (en.hasMoreElements())
                  {
                     aliases.add(en.nextElement());
                  }
                  buf.append("No match for alias: "+alias+", we have aliases " + aliases);
               }
               log.trace(buf.toString());
            }
         }
         catch (KeyStoreException e)
         {
            log.warn("failed to find the certificate for " + alias, e);
         }
         // Ensure that the two certs are equal
         if (cert.equals(storeCert))
            isValid = true;
      }
      else
      {
         log.warn("Domain, KeyStore, or cert is null. Unable to validate the certificate.");
      }

      if( trace )
      {
         log.trace("The supplied certificate "
               + (isValid ? "matched" : "DID NOT match")
               + " the certificate in the keystore.");

         log.trace("exit: validateCredentail(String, X509Certificate)");
      }
      return isValid;
   }

}