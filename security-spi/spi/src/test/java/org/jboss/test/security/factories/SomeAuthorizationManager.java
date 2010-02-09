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
package org.jboss.test.security.factories;

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

//$Id$

/**
 *  Test AuthorizationManager
 *  @author Anil.Saldhana@redhat.com
 *  @since  Oct 11, 2007 
 *  @version $Revision$
 */
public class SomeAuthorizationManager implements AuthorizationManager
{ 
   public SomeAuthorizationManager(String securityDomain)
   { 
   }
   
   public int authorize(Resource resource) throws AuthorizationException
   {
      return 0;
   }

   public Set<Principal> getUserRoles(Principal principal)
   {
      return null;
   }

   public String getSecurityDomain()
   {
      return null;
   }

   public boolean doesUserHaveRole(Principal principal, Set<Principal> roles)
   { 
      return false;
   }

   public <T> EntitlementHolder<T> getEntitlements(Class<T> clazz, Resource resource,
         Identity identity) throws AuthorizationException
   { 
      return null;
   }

   public Group getTargetRoles(Principal targetPrincipal, Map<String, Object> contextMap)
   { 
      return null;
   }

   public int authorize(Resource resource, Subject subject) throws AuthorizationException
   { 
      return 0;
   }
   
   public int authorize(Resource resource, Subject subject,
         RoleGroup role) throws AuthorizationException
   { 
      return 0;
   }

   public int authorize(Resource resource,  Subject subject,
         Group roleGroup) throws AuthorizationException
   { 
      return 0;
   }

   public int authorize(Resource resource, Identity identity, Permission permission) throws AuthorizationException
   {
      return 0;
   }

   public RoleGroup getSubjectRoles(Subject authenticatedSubject, CallbackHandler cbh)
   {
      return null;
   } 
}