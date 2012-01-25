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
package org.jboss.test.security.securitycontext;

import java.security.Principal;

import javax.security.auth.Subject;

import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextUtil;
import org.jboss.security.SecurityIdentity;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.identity.extensions.CredentialIdentity;
 
/**
 *  Test Security Context Util
 *  @author Anil.Saldhana@redhat.com
 *  @since  Feb 25, 2008 
 *  @version $Revision$
 */
public class TestSecurityContextUtil extends SecurityContextUtil
{ 
   public TestSecurityContextUtil(SecurityContext sc)
   {
      this.securityContext = sc;
   }
   
   @Override
   public <T> T get(String key)
   {
      return null;
   }

   @Override
   public Object getCredential()
   {
      CredentialIdentity<?> ci = this.securityContext.getSubjectInfo().getIdentity(CredentialIdentity.class);
      return ci != null ? ci.getCredential() : null;
   }

   @Override
   public RoleGroup getRoles()
   {
      return null;
   }

   @Override
   public SecurityIdentity getSecurityIdentity()
   {
      return null;
   }

   @Override
   public Subject getSubject()
   {
      return this.securityContext.getSubjectInfo().getAuthenticatedSubject();
   }

   @Override
   public String getUserName()
   {
      return getUserPrincipal().getName();
   }

   @Override
   public Principal getUserPrincipal()
   {
      CredentialIdentity<?> ci = this.securityContext.getSubjectInfo().getIdentity(CredentialIdentity.class);
      return ci != null ? ci.asPrincipal() : null;
   }

   @Override
   public <T> T remove(String key)
   {
      return null;
   }

   @Override
   public <T> void set(String key, T obj)
   {
   }

   @Override
   public void setRoles(RoleGroup roles)
   {
   }

   @Override
   public void setSecurityIdentity(SecurityIdentity si)
   {
   }
}