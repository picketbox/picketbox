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
package org.jboss.test.security.microcontainer.metadata.support;

import java.security.Principal;
import java.security.acl.Group;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;

import org.jboss.security.AuthorizationManager;
import org.jboss.security.authorization.AuthorizationException;
import org.jboss.security.authorization.EntitlementHolder;
import org.jboss.security.authorization.Permission;
import org.jboss.security.authorization.Resource;
import org.jboss.security.identity.Identity;
import org.jboss.security.identity.RoleGroup;

/**
 * <p>
 * A mock {@code AuthorizationManager} implementation used in the tests.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class MockAuthorizationManager implements AuthorizationManager
{

   private final String domainName;

   /**
    * <p>
    * Creates an instance of {@code MockAuthorizationManager} using the specified security domain name.
    * </p>
    * 
    * @param domainName a {@code String} representing the name of the security domain.
    */
   public MockAuthorizationManager(String domainName)
   {
      this.domainName = domainName;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.AuthorizationManager#authorize(org.jboss.security.authorization.Resource)
    */
   public int authorize(Resource resource) throws AuthorizationException
   {
      return 0;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.AuthorizationManager#authorize(org.jboss.security.authorization.Resource,
    *      javax.security.auth.Subject)
    */
   public int authorize(Resource resource, javax.security.auth.Subject subject) throws AuthorizationException
   {
      return 0;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.AuthorizationManager#authorize(org.jboss.security.authorization.Resource,
    *      javax.security.auth.Subject, org.jboss.security.identity.RoleGroup)
    */
   public int authorize(Resource resource, Subject subject, RoleGroup group) throws AuthorizationException
   {
      return 0;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.AuthorizationManager#authorize(org.jboss.security.authorization.Resource,
    *      javax.security.auth.Subject, java.security.acl.Group)
    */
   public int authorize(Resource resource, Subject subject, Group group) throws AuthorizationException
   {
      return 0;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.AuthorizationManager#authorize(org.jboss.security.authorization.Resource,
    *      org.jboss.security.identity.Identity, org.jboss.security.authorization.Permission)
    */
   public int authorize(final Resource resource, Identity identity, Permission permission)
         throws AuthorizationException
   {
      return 0;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.AuthorizationManager#doesUserHaveRole(java.security.Principal, java.util.Set)
    */
   public boolean doesUserHaveRole(Principal principal, Set<Principal> roles)
   {
      return false;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.AuthorizationManager#getEntitlements(java.lang.Class,
    *      org.jboss.security.authorization.Resource, org.jboss.security.identity.Identity)
    */
   public <T> EntitlementHolder<T> getEntitlements(Class<T> clazz, Resource resource, Identity identity)
         throws AuthorizationException
   {
      return null;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.AuthorizationManager#getSubjectRoles(javax.security.auth.Subject,
    *      javax.security.auth.callback.CallbackHandler)
    */
   public RoleGroup getSubjectRoles(Subject subject, CallbackHandler handler)
   {
      return null;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.AuthorizationManager#getTargetRoles(java.security.Principal, java.util.Map)
    */
   public Group getTargetRoles(Principal principal, Map<String, Object> options)
   {
      return null;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.AuthorizationManager#getUserRoles(java.security.Principal)
    */
   @Deprecated
   public Set<Principal> getUserRoles(Principal principal)
   {
      return null;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.BaseSecurityManager#getSecurityDomain()
    */
   public String getSecurityDomain()
   {
      return this.domainName;
   }

}
