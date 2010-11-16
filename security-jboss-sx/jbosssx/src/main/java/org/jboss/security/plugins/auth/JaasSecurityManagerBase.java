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
package org.jboss.security.plugins.auth;

import java.lang.reflect.Method;
import java.lang.reflect.UndeclaredThrowableException;
import java.security.Principal;
import java.security.acl.Group;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.jboss.logging.Logger;
import org.jboss.security.AuthenticationManager;
import org.jboss.security.AuthorizationManager;
import org.jboss.security.RealmMapping;
import org.jboss.security.SecurityConstants;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.SecurityUtil;
import org.jboss.security.SubjectSecurityManager;
import org.jboss.security.auth.callback.JBossCallbackHandler;
import org.jboss.util.CachePolicy;
import org.jboss.util.TimedCachePolicy;

/** The JaasSecurityManager is responsible both for authenticating credentials
 associated with principals and for role mapping. This implementation relies
 on the JAAS LoginContext/LoginModules associated with the security
 domain name associated with the class for authentication,
 and the context JAAS Subject object for role mapping.
 
 @see #isValid(Principal, Object, Subject)
 @see #getPrincipal(Principal)
 @see #doesUserHaveRole(Principal, Set)
 
 @author <a href="on@ibis.odessa.ua">Oleg Nitz</a>
 @author Scott.Stark@jboss.org
 @author Anil.Saldhana@jboss.org
 @version $Revision: 62860 $
*/
public class JaasSecurityManagerBase 
   implements SubjectSecurityManager, RealmMapping
{
   /** The authentication cache object.
    */
   public static class DomainInfo implements TimedCachePolicy.TimedEntry
   {
      private static Logger log = Logger.getLogger(DomainInfo.class);
      private static boolean trace = log.isTraceEnabled();
      protected LoginContext loginCtx;
      protected Subject subject;
      protected Object credential;
      protected Principal callerPrincipal;
      private long expirationTime;
      /** Is there an active authentication in process */
      private boolean needsDestroy;
      /** The number of users sharing this DomainInfo */
      private int activeUsers;

      /**
       Create a cache entry with the given lifetime in seconds. Since this comes
       from the TimedCachePolicy, its expected to be <= Integer.MAX_VALUE.
       
       @param lifetime - lifetime in seconds. A lifetime <= 0 means no caching
         with the exception of -1 which indicates that the cache entry never
         expires.
       */
      public DomainInfo(long lifetime)
      {
         expirationTime = lifetime;
         if( expirationTime != -1 )
            expirationTime *= 1000;
      }

      synchronized int acquire()
      {
         return activeUsers ++;
      }
      synchronized int release()
      {
         int users = activeUsers --;
         if( needsDestroy == true && users == 0 )
         {
            if( trace )
               log.trace("needsDestroy is true, doing logout");
            logout();
         }
         return users;
      }
      synchronized void logout()
      {
         if( trace )
            log.trace("logout, subject="+subject+", this="+this);
         try
         {
            if( loginCtx != null )
               loginCtx.logout();
         }
         catch(Throwable e)
         {
            if( trace )
               log.trace("Cache entry logout failed", e);
         }
      }

      public void init(long now)
      {
         expirationTime += now;
      }
      public boolean isCurrent(long now)
      {
         boolean isCurrent = expirationTime == -1;
         if( isCurrent == false )
            isCurrent = expirationTime > now;
         return isCurrent;
      }
      public boolean refresh()
      {
         return false;
      }
      /**
       * This 
       */ 
      public void destroy()
      {
         if( trace )
         {
            log.trace("destroy, subject="+subject+", this="+this
               +", activeUsers="+activeUsers);
         }

         synchronized( this )
         {
            if( activeUsers == 0 )
               logout();
            else
            {
               if( trace )
                  log.trace("destroy saw activeUsers="+activeUsers);
               needsDestroy = true;
            }
         }
      }
      public Object getValue()
      {
         return this;
      }
      public String toString()
      {
         StringBuffer tmp = new StringBuffer(super.toString());
         tmp.append('[');
         tmp.append(SubjectActions.toString(subject));
         tmp.append(",credential.class=");
         if( credential != null )
         {
            Class<?> c = credential.getClass();
            tmp.append(c.getName());
            tmp.append('@');
            tmp.append(System.identityHashCode(c));
         }
         else
         {
            tmp.append("null");
         }
         tmp.append(",expirationTime=");
         tmp.append(expirationTime);
         tmp.append(']');

         return tmp.toString();
      }
   }

   /** The name of the domain this instance is securing. It is used as
    the appName into the SecurityPolicy.
    */
   private String securityDomain;
   /** A cache of DomainInfo objects keyd by Principal. This is now
    always set externally by our security manager service.
    */
   private CachePolicy domainCache;
   /** The JAAS callback handler to use in defaultLogin */
   private CallbackHandler handler;
   /** The setSecurityInfo(Principal, Object) method of the handler obj */
   private transient Method setSecurityInfo;
   /** The flag to indicate that the Subject sets need to be deep copied*/
   private boolean deepCopySubjectOption = false; 
   
   /** The log4j category for the security manager domain
    */
   protected Logger log;
   protected boolean trace;
   private AuthorizationManager authorizationManager;

   /** Creates a default JaasSecurityManager for with a securityDomain
    name of 'other'.
    */
   public JaasSecurityManagerBase()
   {
      this(SecurityConstants.DEFAULT_APPLICATION_POLICY, new JBossCallbackHandler());
   }
   /** Creates a JaasSecurityManager for with a securityDomain
    name of that given by the 'securityDomain' argument.
    @param securityDomain the name of the security domain
    @param handler the JAAS callback handler instance to use
    @exception UndeclaredThrowableException thrown if handler does not
      implement a setSecurityInfo(Princpal, Object) method
    */
   public JaasSecurityManagerBase(String securityDomain, CallbackHandler handler)
   {
      this.securityDomain = SecurityUtil.unprefixSecurityDomain( securityDomain );
      this.handler = handler;
      String categoryName = getClass().getName()+'.'+securityDomain;
      this.log = Logger.getLogger(categoryName);
      this.trace = log.isTraceEnabled();

      // Get the setSecurityInfo(Principal principal, Object credential) method
      Class<?>[] sig = {Principal.class, Object.class};
      try
      {
         setSecurityInfo = handler.getClass().getMethod("setSecurityInfo", sig);
      }
      catch (Exception e)
      {
         String msg = "Failed to find setSecurityInfo(Princpal, Object) method in handler";
         throw new UndeclaredThrowableException(e, msg);
      } 
      log.debug("CallbackHandler: "+handler);
   }

   /** The domainCache is typically a shared object that is populated
    by the login code(LoginModule, etc.) and read by this class in the
    isValid() method.
    @see #isValid(Principal, Object, Subject)
    */
   public void setCachePolicy(CachePolicy domainCache)
   {
      this.domainCache = domainCache;
      log.debug("CachePolicy set to: "+domainCache);
   }

   /**
    * Flag to specify if deep copy of subject sets needs to be 
    * enabled
    * 
    * @param flag
    */
   public void setDeepCopySubjectOption(Boolean flag)
   {
      log.debug("setDeepCopySubjectOption="+ flag);
      this.deepCopySubjectOption = (flag == Boolean.TRUE) ;
   } 
   
   /**
    * Set an AuthorizationManager
    * @param authorizationManager
    */
   public void setAuthorizationManager(AuthorizationManager authorizationManager)
   {
      this.authorizationManager = authorizationManager;
   }
   
   /** Not really used anymore as the security manager service manages the
    security domain authentication caches.
    */
   public void flushCache()
   {
      if( domainCache != null )
         domainCache.flush();
   }

   /** Get the name of the security domain associated with this security mgr.
    @return Name of the security manager security domain.
    */
   public String getSecurityDomain()
   {
      return securityDomain;
   }

   /** Get the currently authenticated Subject. This is a thread local
    property shared across all JaasSecurityManager instances.
    @return The Subject authenticated in the current thread if one
    exists, null otherwise.
    */
   public Subject getActiveSubject()
   {
      /* This does not use SubjectActions.getActiveSubject since the caller
         must have the correct permissions to access the
         SecurityAssociation.getSubject method.
      */
      //return SecurityAssociation.getSubject();
      Subject subj = null;
      SecurityContext sc = SecurityContextAssociation.getSecurityContext();
      if(sc != null)
      {
         subj = sc.getUtil().getSubject();
      }
      return subj;
   }

   /** Validate that the given credential is correct for principal. This
    returns the value from invoking isValid(principal, credential, null).
    @param principal - the security domain principal attempting access
    @param credential - the proof of identity offered by the principal
    @return true if the principal was authenticated, false otherwise.
    */
   public boolean isValid(Principal principal, Object credential)
   {
      return isValid(principal, credential, null);
   }

   /** Validate that the given credential is correct for principal. This first
    will check the current CachePolicy object if one exists to see if the
    user's cached credentials match the given credential. If there is no
    credential cache or the cache information is invalid or does not match,
    the user is authenticated against the JAAS login modules configured for
    the security domain.
    @param principal - the security domain principal attempting access
    @param credential  the proof of identity offered by the principal
    @param activeSubject - if not null, a Subject that will be populated with
      the state of the authenticated Subject.
    @return true if the principal was authenticated, false otherwise.
    */
   public boolean isValid(Principal principal, Object credential,
      Subject activeSubject)
   {
      // Check the cache first
      DomainInfo cacheInfo = getCacheInfo(principal, true);
      if( trace )
         log.trace("Begin isValid, principal:"+principal+", cache info: "+cacheInfo);

      boolean isValid = false;
      if( cacheInfo != null )
      {
         isValid = validateCache(cacheInfo, credential, activeSubject);
         if( cacheInfo != null )
            cacheInfo.release();
      }
      if( isValid == false )
         isValid = authenticate(principal, credential, activeSubject);
      if( trace )
         log.trace("End isValid, "+isValid); 
      return isValid;
   } 

   
   /** Map the argument principal from the deployment environment principal
    to the developer environment. This is called by the EJB context
    getCallerPrincipal() to return the Principal as described by
    the EJB developer domain.
    @return a Principal object that is valid in the deployment environment
    if one exists. If no Subject exists or the Subject has no principals
    then the argument principal is returned.
    */
   public Principal getPrincipal(Principal principal)
   {
      if(domainCache == null)
         return principal;
      Principal result = principal; 
      // Get the CallerPrincipal group member
      synchronized( domainCache )
      {
         DomainInfo info = getCacheInfo(principal, false);
         if( trace )
            log.trace("getPrincipal, cache info: "+info);
         if( info != null )
         {
            result = info.callerPrincipal;
            // If the mapping did not have a callerPrincipal just use principal
            if( result == null )
               result = principal;
            info.release();
         }
      }

      return result;
   }

   /** Does the current Subject have a role(a Principal) that equates to one
    of the role names. This method obtains the Group named 'Roles' from
    the principal set of the currently authenticated Subject as determined
    by the SecurityAssociation.getSubject() method and then creates a
    SimplePrincipal for each name in roleNames. If the role is a member of the
    Roles group, then the user has the role. This requires that the caller
    establish the correct SecurityAssociation subject prior to calling this
    method. In the past this was done as a side-effect of an isValid() call,
    but this is no longer the case.

    @param principal - ignored. The current authenticated Subject determines
    the active user and assigned user roles.
    @param rolePrincipals - a Set of Principals for the roles to check.
    
    @see java.security.acl.Group;
    @see Subject#getPrincipals()
    */
   public boolean doesUserHaveRole(Principal principal, Set<Principal> rolePrincipals)
   { 
      if(this.authorizationManager == null)
      {
         this.authorizationManager = SecurityUtil.getAuthorizationManager(securityDomain, 
               SecurityConstants.JAAS_CONTEXT_ROOT); 
      }
      if(this.authorizationManager == null)
      {
         if(trace)
            log.trace("doesUserHaveRole:AuthorizationManager is null");
         return false;
      }
      return authorizationManager.doesUserHaveRole(principal, rolePrincipals); 
   } 

   /** Return the set of domain roles the current active Subject 'Roles' group
      found in the subject Principals set.

    @param principal - ignored. The current authenticated Subject determines
    the active user and assigned user roles.
    @return The Set<Principal> for the application domain roles that the
    principal has been assigned.
   */
   @SuppressWarnings("deprecation")
   public Set<Principal> getUserRoles(Principal principal)
   {
      if(this.authorizationManager == null)
      {
         this.authorizationManager = SecurityUtil.getAuthorizationManager(securityDomain, 
               SecurityConstants.JAAS_CONTEXT_ROOT); 
      }
      if(this.authorizationManager == null)
      {
         log.trace("doesUserHaveRole:AuthorizationManager is null");
         return null;
      }
      return authorizationManager.getUserRoles(principal);
   } 
   
   /**
    * @see AuthenticationManager#getTargetPrincipal(Principal,Map)
    */
   public Principal getTargetPrincipal(Principal anotherDomainPrincipal, 
         Map<String,Object> contextMap)
   {
      throw new RuntimeException("Not implemented yet");
   }

   /** Currently this simply calls defaultLogin() to do a JAAS login using the
    security domain name as the login module configuration name.
    
    * @param principal - the user id to authenticate
    * @param credential - an opaque credential.
    * @return false on failure, true on success.
    */
   private boolean authenticate(Principal principal, Object credential,
      Subject theSubject)
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
         if( subject != null )
         {
            // Copy the current subject into theSubject
            if( theSubject != null )
            {
               SubjectActions.copySubject(subject, theSubject, false,this.deepCopySubjectOption);
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
      catch(LoginException e)
      {
         // Don't log anonymous user failures unless trace level logging is on
         if( principal != null && principal.getName() != null || trace )
            log.trace("Login failure", e);
         authException = e;
      }
      // Set the security association thread context info exception
      SubjectActions.setContextInfo("org.jboss.security.exception", authException);

      return authenticated;
   }

   /** Pass the security info to the login modules configured for
    this security domain using our SecurityAssociationHandler.
    @return The authenticated Subject if successful.
    @exception LoginException throw if login fails for any reason.
    */
   private LoginContext defaultLogin(Principal principal, Object credential)
      throws LoginException
   {
      /* We use our internal CallbackHandler to provide the security info. A
      copy must be made to ensure there is a unique handler per active
      login since there can be multiple active logins.
      */
      Object[] securityInfo = {principal, credential};
      CallbackHandler theHandler = null;
      try
      {
         theHandler = (CallbackHandler) handler.getClass().newInstance();
         setSecurityInfo.invoke(theHandler, securityInfo);
      }
      catch (Throwable e)
      {
         if( trace )
            log.trace("Failed to create/setSecurityInfo on handler", e);
         LoginException le = new LoginException("Failed to setSecurityInfo on handler");
         le.initCause(e);
         throw le;
      }
      Subject subject = new Subject();
      LoginContext lc = null;
      if( trace )
         log.trace("defaultLogin, principal="+principal);
      lc = SubjectActions.createLoginContext(securityDomain, subject, theHandler);
      lc.login();
      if( trace )
         log.trace("defaultLogin, lc="+lc+", subject="+SubjectActions.toString(subject));
      return lc;
   }

   /** Validate the cache credential value against the provided credential
    */
   @SuppressWarnings("unchecked")
   private boolean validateCache(DomainInfo info, Object credential,
      Subject theSubject)
   {
      if( trace )
      {
         StringBuffer tmp = new StringBuffer("Begin validateCache, info=");
         tmp.append(info.toString());
         tmp.append(";credential.class=");
         if( credential != null )
         {
            Class c = credential.getClass();
            tmp.append(c.getName());
            tmp.append('@');
            tmp.append(System.identityHashCode(c));
         }
         else
         {
            tmp.append("null");
         }
         log.trace(tmp.toString());
      }

      Object subjectCredential = info.credential;
      boolean isValid = false;
      // Check for a null credential as can be the case for an anonymous user
      if( credential == null || subjectCredential == null )
      {
         // Both credentials must be null
         isValid = (credential == null) && (subjectCredential == null);
      }
      // See if the credential is assignable to the cache value
      else if( subjectCredential.getClass().isAssignableFrom(credential.getClass()) )
      {
        /* Validate the credential by trying Comparable, char[], byte[],
         Object[], and finally Object.equals()
         */
         if( subjectCredential instanceof Comparable )
         {
            Comparable c = (Comparable) subjectCredential;
            isValid = c.compareTo(credential) == 0;
         }
         else if( subjectCredential instanceof char[] )
         {
            char[] a1 = (char[]) subjectCredential;
            char[] a2 = (char[]) credential;
            isValid = Arrays.equals(a1, a2);
         }
         else if( subjectCredential instanceof byte[] )
         {
            byte[] a1 = (byte[]) subjectCredential;
            byte[] a2 = (byte[]) credential;
            isValid = Arrays.equals(a1, a2);
         }
         else if( subjectCredential.getClass().isArray() )
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
      else if( subjectCredential instanceof char[] && credential instanceof String )
      {
         char[] a1 = (char[]) subjectCredential;
         char[] a2 = ((String) credential).toCharArray();
         isValid = Arrays.equals(a1, a2);
      }
      else if( subjectCredential instanceof String && credential instanceof char[] )
      {
         char[] a1 = ((String) subjectCredential).toCharArray();
         char[] a2 = (char[]) credential;
         isValid = Arrays.equals(a1, a2);         
      }

      // If the credentials match, set the thread's active Subject
      if( isValid )
      {
         // Copy the current subject into theSubject
         if( theSubject != null )
         {
            SubjectActions.copySubject(info.subject, theSubject, false,this.deepCopySubjectOption);
         }
      }
      if( trace )
         log.trace("End validateCache, isValid="+isValid);

      return isValid;
   }
 
   /** An accessor method that synchronizes access on the domainCache
    to avoid a race condition that can occur when the cache entry expires
    in the presence of multi-threaded access. The allowRefresh flag should
    be true for authentication accesses and false for other accesses.
    Previously the other accesses included authorization and caller principal
    mapping. Now the only use of the 

    @param principal - the caller identity whose cached credentials are to
    be accessed.
    @param allowRefresh - a flag indicating if the cache access should flush
    any expired entries.
    */
   private DomainInfo getCacheInfo(Principal principal, boolean allowRefresh)
   {
      if( domainCache == null )
         return null;

      DomainInfo cacheInfo = null;
      synchronized( domainCache )
      {
          if( allowRefresh == true )
            cacheInfo = (DomainInfo) domainCache.get(principal);
          else
            cacheInfo = (DomainInfo) domainCache.peek(principal);
         if( cacheInfo != null )
            cacheInfo.acquire();
      }
      return cacheInfo;
   }

   private Subject updateCache(LoginContext lc, Subject subject,
      Principal principal, Object credential)
   {
      // If we don't have a cache there is nothing to update
      if( domainCache == null )
         return subject;

      long lifetime = 0;
      if( domainCache instanceof TimedCachePolicy )
      {
         TimedCachePolicy cache = (TimedCachePolicy) domainCache;
         lifetime = cache.getDefaultLifetime();
      }
      DomainInfo info = new DomainInfo(lifetime);
      info.loginCtx = lc;
      info.subject = new Subject();
      SubjectActions.copySubject(subject, info.subject, true, this.deepCopySubjectOption);
      info.credential = credential;

      if( trace )
      {
         log.trace("updateCache, inputSubject="+SubjectActions.toString(subject)
            +", cacheSubject="+SubjectActions.toString(info.subject));
      }

     /* Get the Subject callerPrincipal by looking for a Group called
        'CallerPrincipal'
      */
      Set<Group> subjectGroups = subject.getPrincipals(Group.class);
      Iterator<Group> iter = subjectGroups.iterator();
      while( iter.hasNext() )
      {
         Group grp = iter.next();
         String name = grp.getName();
         if( name.equals("CallerPrincipal") )
         {
            Enumeration<? extends Principal> members = grp.members();
            if( members.hasMoreElements() )
               info.callerPrincipal = members.nextElement();
         }
      }
      
     /* Handle null principals with no callerPrincipal. This is an indication
        of an user that has not provided any authentication info, but
        has been authenticated by the domain login module stack. Here we look
        for the first non-Group Principal and use that.
      */
      if( principal == null && info.callerPrincipal == null )
      {
         Set<Principal> subjectPrincipals = subject.getPrincipals(Principal.class);
         Iterator<? extends Principal> iterPrincipals = subjectPrincipals.iterator();
         while( iterPrincipals.hasNext() )
         {
            Principal p = iterPrincipals.next();
            if( (p instanceof Group) == false )
               info.callerPrincipal = p;
         }
      }

     /* If the user already exists another login is active. Currently
        only one is allowed so remove the old and insert the new. Synchronize
        on the domainCache to ensure the removal and addition are an atomic
        operation so that getCacheInfo cannot see stale data.
      */
      synchronized( domainCache )
      {
         if( domainCache.peek(principal) != null )
            domainCache.remove(principal);
         domainCache.insert(principal, info);
         if( trace )
            log.trace("Inserted cache info: "+info);
      }
      return info.subject;
   } 
}