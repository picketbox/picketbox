/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat Middleware LLC, and individual contributors
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
package org.jboss.security.authentication;

import java.io.Serializable;
import java.lang.reflect.Method;
import java.security.Principal;
import java.security.acl.Group;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.jboss.security.AuthenticationManager;
import org.jboss.security.CacheableManager;
import org.jboss.security.PicketBoxLogger;
import org.jboss.security.PicketBoxMessages;
import org.jboss.security.SecurityConstants;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.auth.callback.JBossCallbackHandler;
import org.jboss.security.auth.login.BaseAuthenticationInfo;
import org.jboss.security.authentication.JBossCachedAuthenticationManager.DomainInfo;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.SecurityConfiguration;
import org.jboss.security.plugins.ClassLoaderLocator;
import org.jboss.security.plugins.ClassLoaderLocatorFactory;

/**
 * {@link AuthenticationManager} implementation that uses {@code CacheableManager} as the cache provider.
 * 
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @author <a href="on@ibis.odessa.ua">Oleg Nitz</a>
 * @author Scott.Stark@jboss.org
 * @author Anil.Saldhana@jboss.org
 */
public class JBossCachedAuthenticationManager implements AuthenticationManager, CacheableManager<ConcurrentMap<Principal, DomainInfo>, Principal>
{

   private String securityDomain;

   private CallbackHandler callbackHandler;

   private transient Method setSecurityInfo;

   protected ConcurrentMap<Principal, DomainInfo> domainCache;

   private boolean deepCopySubjectOption = false;

   /**
    * Create a new JBossCachedAuthenticationManager using the
    * default security domain and {@link CallbackHandler} implementation.
    */
   public JBossCachedAuthenticationManager()
   {
      this(SecurityConstants.DEFAULT_APPLICATION_POLICY, new JBossCallbackHandler());
   }

   /**
    * Create a new JBossCachedAuthenticationManager.
    * 
    * @param securityDomain name of the security domain
    * @param callbackHandler {@link CallbackHandler} implementation
    */
   public JBossCachedAuthenticationManager(String securityDomain, CallbackHandler callbackHandler)
   {
      this.securityDomain = securityDomain;
      this.callbackHandler = callbackHandler;

      // Get the setSecurityInfo(Principal principal, Object credential) method
      Class<?>[] sig = {Principal.class, Object.class};
      try
      {
         setSecurityInfo = callbackHandler.getClass().getMethod("setSecurityInfo", sig);
      }
      catch (Exception e)
      {
         throw new UnsupportedOperationException(PicketBoxMessages.MESSAGES.unableToFindSetSecurityInfoMessage());
      }
   }

   @Override
   public Subject getActiveSubject()
   {
      Subject subj = null;
      SecurityContext sc = SecurityContextAssociation.getSecurityContext();
      if (sc != null)
      {
         subj = sc.getUtil().getSubject();
      }
      return subj;
   }

   @Override
   public Principal getTargetPrincipal(Principal anotherDomainPrincipal, Map<String, Object> contextMap)
   {
      throw new UnsupportedOperationException();
   }

   @Override
   public boolean isValid(Principal principal, Object credential)
   {
      return isValid(principal, credential, null);
   }

   @Override
   public boolean isValid(Principal principal, Object credential, Subject activeSubject)
   {
      // first check cache
      DomainInfo cachedEntry = getCacheInfo(principal);
      PicketBoxLogger.LOGGER.traceBeginIsValid(principal, cachedEntry != null ? cachedEntry.toString() : null);

      boolean isValid = false;
      if (cachedEntry != null)
      {
         isValid = validateCache(cachedEntry, credential, activeSubject);
      }

      if (!isValid)
         isValid = authenticate(principal, credential, activeSubject);

      PicketBoxLogger.LOGGER.traceEndIsValid(isValid);
      return isValid;
   }

   @Override
   public String getSecurityDomain()
   {
      return securityDomain;
   }

   @Override
   public void flushCache()
   {
      PicketBoxLogger.LOGGER.traceFlushWholeCache();
      if (domainCache != null)
         domainCache.clear();
   }

   @Override
   public void flushCache(Principal key)
   {
      if (domainCache != null && key != null) {
         PicketBoxLogger.LOGGER.traceFlushCacheEntry(key.getName());
         domainCache.remove(key);
      }
   }

   @Override
   public void setCache(ConcurrentMap<Principal, DomainInfo> cache)
   {
      this.domainCache = cache;
   }

   @Override
   public boolean containsKey(Principal key)
   {
      if (domainCache != null && key != null)
         return domainCache.containsKey(key);
      return false;
   }
   
   @Override
   public Set<Principal> getCachedKeys()
   {
      if (domainCache != null)
         return domainCache.keySet();
      return null;
   }

   /**
    * Flag to specify if deep copy of subject sets needs to be 
    * enabled
    * 
    * @param flag
    */
   public void setDeepCopySubjectOption(Boolean flag)
   {
      deepCopySubjectOption = flag.booleanValue();
   }

   /**
    * Retrieve on entry from the cache.
    * 
    * @param principal entry's key
    * @return entry's value or null if not found
    */
   private DomainInfo getCacheInfo(Principal principal)
   {
      if (domainCache != null && principal != null)
         return domainCache.get(principal);
      return null;
   }

   /**
    * Validate the cache credential value against the provided credential
    */
   @SuppressWarnings({"rawtypes", "unchecked"})
   private boolean validateCache(DomainInfo info, Object credential, Subject theSubject)
   {

      PicketBoxLogger.LOGGER.traceBeginValidateCache(info.toString(), credential != null ? credential.getClass() : null);

      Object subjectCredential = info.credential;
      boolean isValid = false;
      // Check for a null credential as can be the case for an anonymous user
      if (credential == null || subjectCredential == null)
      {
         // Both credentials must be null
         isValid = (credential == null) && (subjectCredential == null);
      }
      // See if the credential is assignable to the cache value
      else if (subjectCredential.getClass().isAssignableFrom(credential.getClass()))
      {
         // Validate the credential by trying Comparable, char[], byte[], Object[], and finally Object.equals()
         if (subjectCredential instanceof Comparable)
         {
            Comparable c = (Comparable) subjectCredential;
            isValid = c.compareTo(credential) == 0;
         }
         else if (subjectCredential instanceof char[])
         {
            char[] a1 = (char[]) subjectCredential;
            char[] a2 = (char[]) credential;
            isValid = Arrays.equals(a1, a2);
         }
         else if (subjectCredential instanceof byte[])
         {
            byte[] a1 = (byte[]) subjectCredential;
            byte[] a2 = (byte[]) credential;
            isValid = Arrays.equals(a1, a2);
         }
         else if (subjectCredential.getClass().isArray())
         {
            Object[] a1 = (Object[]) subjectCredential;
            Object[] a2 = (Object[]) credential;
            isValid = Arrays.equals(a1, a2);
         }
         else
         {
            isValid = subjectCredential.equals(credential);
         }
      }
      else if (subjectCredential instanceof char[] && credential instanceof String)
      {
         char[] a1 = (char[]) subjectCredential;
         char[] a2 = ((String) credential).toCharArray();
         isValid = Arrays.equals(a1, a2);
      }
      else if (subjectCredential instanceof String && credential instanceof char[])
      {
         char[] a1 = ((String) subjectCredential).toCharArray();
         char[] a2 = (char[]) credential;
         isValid = Arrays.equals(a1, a2);
      }

      // If the credentials match, set the thread's active Subject
      if (isValid)
      {
         // Copy the current subject into theSubject
         if (theSubject != null)
         {
            SubjectActions.copySubject(info.subject, theSubject, false, this.deepCopySubjectOption);
         }
      }
      PicketBoxLogger.LOGGER.traceEndValidteCache(isValid);
      return isValid;
   }

   /** 
    * Currently this simply calls defaultLogin() to do a JAAS login using the
    * security domain name as the login module configuration name.
    *
    * @param principal - the user id to authenticate
    * @param credential - an opaque credential.
    * @return false on failure, true on success.
    */
   private boolean authenticate(Principal principal, Object credential, Subject theSubject)
   { 
	   ApplicationPolicy theAppPolicy = SecurityConfiguration.getApplicationPolicy(securityDomain);
	   if(theAppPolicy != null)
	   {
		   BaseAuthenticationInfo authInfo = theAppPolicy.getAuthenticationInfo();
		   String jbossModuleName = authInfo.getJBossModuleName();
		   if(jbossModuleName != null)
		   {
			   ClassLoader currentTccl = SubjectActions.getContextClassLoader();
			   ClassLoaderLocator theCLL = ClassLoaderLocatorFactory.get();
			   if(theCLL != null)
			   {
				   ClassLoader newTCCL = theCLL.get(jbossModuleName);
				   if(newTCCL != null)
				   {
					   try
					   {
						   SubjectActions.setContextClassLoader(newTCCL);
						   return proceedWithJaasLogin(principal, credential, theSubject);
					   }
					   finally
					   {
						   SubjectActions.setContextClassLoader(currentTccl);
					   }
				   }
			   }
		   }
	   }
	   return proceedWithJaasLogin(principal, credential, theSubject);
   }
   

   private boolean proceedWithJaasLogin(Principal principal, Object credential, Subject theSubject)
   {
	   Subject subject = null;
	   boolean authenticated = false;
	   LoginException authException = null;
	   try 
	   {
		   // Validate the principal using the login configuration for this domain
		   LoginContext lc = defaultLogin(principal, credential);
		   subject = lc.getSubject();

		   // Set the current subject if login was successful
		   if (subject != null)
		   {
			   // Copy the current subject into theSubject
			   if (theSubject != null)
			   {
				   SubjectActions.copySubject(subject, theSubject, false, this.deepCopySubjectOption);
			   }
			   else
			   {
				   theSubject = subject;
			   }

			   authenticated = true;
			   // Build the Subject based DomainInfo cache value
			   updateCache(lc, subject, principal, credential);
		   }
	   }
	   catch (LoginException e)
	   {
		   // Don't log anonymous user failures unless trace level logging is on
		   if (principal != null && principal.getName() != null)
               PicketBoxLogger.LOGGER.debugFailedLogin(e);
		   authException = e;
	   }
	   // Set the security association thread context info exception
	   SubjectActions.setContextInfo("org.jboss.security.exception", authException);

	   return authenticated;
   }

   /** 
    * Pass the security info to the login modules configured for
    * this security domain using our SecurityAssociationHandler.
    *
    * @return The authenticated Subject if successful.
    * @exception LoginException throw if login fails for any reason.
    */
   private LoginContext defaultLogin(Principal principal, Object credential) throws LoginException
   {
      // We use our internal CallbackHandler to provide the security info. A
      // copy must be made to ensure there is a unique handler per active
      // login since there can be multiple active logins.
      Object[] securityInfo = {principal, credential};
      CallbackHandler theHandler = null;
      try
      {
         theHandler = (CallbackHandler) callbackHandler.getClass().newInstance();
         setSecurityInfo.invoke(theHandler, securityInfo);
      }
      catch (Throwable e)
      {
         LoginException le = new LoginException(PicketBoxMessages.MESSAGES.unableToFindSetSecurityInfoMessage());
         le.initCause(e);
         throw le;
      }
      Subject subject = new Subject();
      LoginContext lc = null;
      PicketBoxLogger.LOGGER.traceDefaultLoginPrincipal(principal);
      lc = SubjectActions.createLoginContext(securityDomain, subject, theHandler);
      lc.login();
      PicketBoxLogger.LOGGER.traceDefaultLoginSubject(lc.toString(), SubjectActions.toString(subject));
      return lc;
   }

   /**
    * Updates the cache either by inserting a new entry or by replacing
    * an invalid (expired) entry.
    * 
    * @param loginContext {@link LoginContext} of the authentication
    * @param subject {@link Subject} resulted from JAAS login
    * @param principal {@link Principal} representing the user's identity
    * @param credential user's proof of identity
    * @return authenticated {@link Subject}
    */
   private Subject updateCache(LoginContext loginContext, Subject subject, Principal principal, Object credential)
   {
      // If we don't have a cache there is nothing to update
      if (domainCache == null || principal == null)
         return subject;

      DomainInfo info = new DomainInfo();
      info.loginContext = loginContext;
      info.subject = new Subject();
      SubjectActions.copySubject(subject, info.subject, true, this.deepCopySubjectOption);
      info.credential = credential;

      PicketBoxLogger.LOGGER.traceUpdateCache(SubjectActions.toString(subject), SubjectActions.toString(info.subject));

      // Get the Subject callerPrincipal by looking for a Group called 'CallerPrincipal'
      Set<Group> subjectGroups = subject.getPrincipals(Group.class);
      Iterator<Group> iter = subjectGroups.iterator();
      while (iter.hasNext())
      {
         Group grp = iter.next();
         String name = grp.getName();
         if (name.equals("CallerPrincipal"))
         {
            Enumeration<? extends Principal> members = grp.members();
            if (members.hasMoreElements())
               info.callerPrincipal = members.nextElement();
         }
      }

      // Handle null principals with no callerPrincipal. This is an indication
      // of an user that has not provided any authentication info, but
      // has been authenticated by the domain login module stack. Here we look
      // for the first non-Group Principal and use that.
      if (info.callerPrincipal == null)
      {
         Set<Principal> subjectPrincipals = subject.getPrincipals(Principal.class);
         Iterator<? extends Principal> iterPrincipals = subjectPrincipals.iterator();
         while (iterPrincipals.hasNext())
         {
            Principal p = iterPrincipals.next();
            if (!(p instanceof Group))
            {
               info.callerPrincipal = p;
               break;
            }
         }
      }

      // If the user already exists another login is active. Currently
      // only one is allowed so remove the old and insert the new
      domainCache.put(principal, info);
      PicketBoxLogger.LOGGER.traceInsertedCacheInfo(info.toString());
      return info.subject;
   }

   /**
    * A cache value. Holds information about the authentication process.
    * 
    * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
    */
   public static class DomainInfo implements Serializable
   {
      private static final long serialVersionUID = 7402775370244483773L;

      protected LoginContext loginContext;

      protected Subject subject;

      protected Object credential;

      protected Principal callerPrincipal;

      public void logout()
      {
         if (loginContext != null)
         {
            try
            {
               loginContext.logout();
            }
            catch (Exception e)
            {
               PicketBoxLogger.LOGGER.traceCacheEntryLogoutFailure(e);
            }
         }
      }
   }
}