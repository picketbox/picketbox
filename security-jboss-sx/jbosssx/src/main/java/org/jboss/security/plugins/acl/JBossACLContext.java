/*
 * JBoss, Home of Professional Open Source
 * Copyright 2007, JBoss Inc., and individual contributors as indicated
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
package org.jboss.security.plugins.acl;

import static org.jboss.security.authorization.AuthorizationContext.DENY;
import static org.jboss.security.authorization.AuthorizationContext.PERMIT;

import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.jboss.logging.Logger;
import org.jboss.security.acl.ACLContext;
import org.jboss.security.acl.ACLPermission;
import org.jboss.security.acl.ACLProvider;
import org.jboss.security.acl.config.ACLProviderEntry;
import org.jboss.security.authorization.AuthorizationException;
import org.jboss.security.authorization.EntitlementHolder;
import org.jboss.security.authorization.Permission;
import org.jboss.security.authorization.Resource;
import org.jboss.security.config.ACLInfo;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.ControlFlag;
import org.jboss.security.config.SecurityConfiguration;
import org.jboss.security.identity.Identity;

// $Id$

/**
 * Default Implementation of ACLContext
 * 
 * @author Anil.Saldhana@redhat.com
 * @since Jan 30, 2008
 * @version $Revision$
 */
public class JBossACLContext extends ACLContext
{
   private static Logger log = Logger.getLogger(JBossACLContext.class);

   private final boolean trace = log.isTraceEnabled();

   public JBossACLContext(String name)
   {
      this.securityDomainName = name;
   }

   @Override
   public <T> EntitlementHolder<T> getEntitlements(final Class<T> clazz, final Resource resource,
         final Identity identity) throws AuthorizationException
   {
      Set<T> aggregateEntitlements = null;

      try
      {
         initializeModules(resource, identity);
      }
      catch (PrivilegedActionException e1)
      {
         throw new RuntimeException(e1);
      }
      // Do a PrivilegedAction
      try
      {
         aggregateEntitlements = AccessController.doPrivileged(new PrivilegedExceptionAction<Set<T>>()
         {
            public Set<T> run() throws AuthorizationException
            {
               Set<T> entitlements = invokeACL(clazz, resource, identity);
               invokeTeardown();

               return entitlements;
            }
         });
      }
      catch (PrivilegedActionException e)
      {
         Exception exc = e.getException();
         if (trace)
            log.trace("Error in authorize:", exc);
         invokeTeardown();
         throw ((AuthorizationException) exc);
      }

      final Set<T> result = aggregateEntitlements;
      return new EntitlementHolder<T>()
      {
         public Set<T> getEntitled()
         {
            return result;
         }
      };
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.acl.ACLContext#authorize(org.jboss.security.authorization.Resource,
    *      org.jboss.security.identity.Identity, org.jboss.security.authorization.Permission)
    */
   @Override
   public int authorize(final Resource resource, final Identity identity, final Permission permission)
         throws AuthorizationException
   {

      if (permission instanceof ACLPermission == false)
         throw new AuthorizationException("Unable to process permission of type " + permission.getClass());

      // instantiate and initialize the ACL modules.
      try
      {
         initializeModules(resource, identity);
      }
      catch (PrivilegedActionException pae)
      {
         throw new RuntimeException(pae);
      }

      // invoke the module's isAccessGranted method to figure out whether identity has or not access to the resource.
      Integer result;
      try
      {
         result = (Integer) AccessController.doPrivileged(new PrivilegedExceptionAction<Object>()
         {
            public Object run() throws AuthorizationException
            {
               return invokeAuthorize(resource, identity, (ACLPermission) permission);
            }
         });
      }
      catch (PrivilegedActionException e)
      {
         Exception exc = e.getException();
         if (trace)
            log.trace("Error authorizing identity " + identity + ":", exc);
         this.invokeTeardown();
         throw ((AuthorizationException) exc);
      }
      return result;
   }

   private void initializeModules(Resource resource, Identity identity) throws PrivilegedActionException
   {
      super.modules.clear();
      ACLInfo aclInfo = getACLInfo(securityDomainName, resource);
      if (aclInfo == null)
         throw new IllegalStateException("ACL Info is null");
      ACLProviderEntry[] entries = aclInfo.getACLProviderEntry();
      int len = entries != null ? entries.length : 0;
      for (int i = 0; i < len; i++)
      {
         ACLProviderEntry entry = entries[i];
         super.modules.add(instantiateModule(entry.getAclProviderName(), entry.getOptions()));
         super.controlFlags.add(entry.getControlFlag());
      }
   }

   private ACLProvider instantiateModule(String name, Map<String, Object> map) throws PrivilegedActionException
   {
      ACLProvider am = null;
      ClassLoader tcl = SecurityActions.getContextClassLoader();
      try
      {
         Class<?> clazz = tcl.loadClass(name);
         am = (ACLProvider) clazz.newInstance();
      }
      catch (Exception e)
      {
         log.debug("Error instantiating AuthorizationModule:", e);
      }
      if (am == null)
         throw new IllegalStateException("ACLProvider has not " + "been instantiated");
      am.initialize(this.sharedState, map);
      return am;
   }

   private <T> Set<T> invokeACL(Class<T> clazz, Resource resource, Identity identity) throws AuthorizationException
   {
      Set<T> entitlements = new HashSet<T>();
      int length = modules.size();
      for (int i = 0; i < length; i++)
      {
         ACLProvider module = modules.get(i);
         try
         {
            Set<T> er = module.getEntitlements(clazz, resource, identity);
            if (er == null)
               throw new AuthorizationException("module " + module.getClass().getName()
                     + " generated null entitlements.");
            entitlements.addAll(er);
         }
         catch (Exception ae)
         {
            throw new AuthorizationException(ae.getMessage());
         }
      }
      return entitlements;
   }

   /**
    * <p>
    * This method calls the configured ACL modules in order to determine of the specified identity has the expected
    * permissions to access a resource.
    * </p>
    * 
    * @param resource the {@code Resource} that is to be accessed by the specified identity.
    * @param identity the {@code Identity} trying to access the resource.
    * @param permission the expected permissions of the identity.
    * @return {@code AuthorizationContext#PERMIT} if the identity is has the expected permissions;
    *         {@code AuthorizationContext#DENY} otherwise.
    * @throws AuthorizationException if an error occurs while calling the ACL modules.
    */
   private int invokeAuthorize(Resource resource, Identity identity, ACLPermission permission)
         throws AuthorizationException
   {
      // if there are no ACL modules, allow access to the resource.
      if (super.modules == null || super.modules.size() == 0)
         return PERMIT;

      boolean encounteredRequiredError = false;
      int overallDecision = DENY;

      for (int i = 0; i < super.modules.size(); i++)
      {
         ACLProvider module = super.modules.get(i);
         ControlFlag flag = super.controlFlags.get(i);
         int decision = DENY;
         try
         {
            decision = module.isAccessGranted(resource, identity, permission) ? PERMIT : DENY;
            if (trace)
               log.trace("ACL module " + module.getClass().getName() + (decision == PERMIT ? " granted " : " denied ")
                     + "access to resource " + resource);
            // if decision is PERMIT and module is SUFFICIENT, the overall result is PERMIT.
            if (decision == PERMIT)
            {
               overallDecision = PERMIT;
               if (flag == ControlFlag.SUFFICIENT && encounteredRequiredError == false)
               {
                  if (trace)
                     log.trace("SUFFICIENT module succeeded: overall status=PERMIT");
                  break;
               }
            }
            // if decision is DENY and module is REQUISITE, the overall result is DENY.
            else if (flag == ControlFlag.REQUISITE)
            {
               if (trace)
                  log.trace("REQUISITE module failed: overall status=DENY");
               overallDecision = DENY;
               break;
            }
            // if decision is DENY and module is REQUIRED, set flag indicating the required module failed.
            else if (flag == ControlFlag.REQUIRED)
            {
               if (trace)
                  log.trace("REQUIRED module failed: overall status=DENY");
               encounteredRequiredError = true;
            }
         }
         catch (Exception ae)
         {
            throw new AuthorizationException(ae.getMessage());
         }
      }
      if (encounteredRequiredError == true)
         overallDecision = DENY;

      return overallDecision;
   }

   private ACLInfo getACLInfo(String domainName, Resource resource)
   {
      ApplicationPolicy aPolicy = SecurityConfiguration.getApplicationPolicy(domainName);

      if (aPolicy == null)
      {
         if (trace)
            log.trace("Application Policy not obtained for domain=" + domainName
                  + ". Trying to obtain the App policy for the default domain of the layer:");
         aPolicy = SecurityConfiguration.getApplicationPolicy(resource.getLayer().name());
      }
      if (aPolicy == null)
         throw new IllegalStateException("Application Policy is null for domain:" + domainName);

      return aPolicy.getAclInfo();
   }

   private void invokeTeardown() throws AuthorizationException
   {
      int length = modules.size();
      for (int i = 0; i < length; i++)
      {
         ACLProvider module = modules.get(i);
         boolean bool = module.tearDown();
         if (!bool)
            throw new AuthorizationException("TearDown on module failed:" + module.getClass());
      }
      modules.clear();
   }

   @Override
   public String toString()
   {
      StringBuilder builder = new StringBuilder();
      builder.append("[").append(getClass().getCanonicalName()).append("()");
      builder.append(this.securityDomainName).append(")]");
      return builder.toString();
   }
}