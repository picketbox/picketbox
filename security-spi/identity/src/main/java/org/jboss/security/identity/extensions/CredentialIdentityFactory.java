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
package org.jboss.security.identity.extensions;

import java.security.Principal;
import java.security.acl.Group;

import org.jboss.security.identity.IdentityFactory;
import org.jboss.security.identity.Role;
 
/**
 *  Factory to create Credential Identity
 *  @author Anil.Saldhana@redhat.com
 *  @since  Feb 25, 2008 
 *  @version $Revision$
 */
public class CredentialIdentityFactory extends IdentityFactory
{
   private static CredentialIdentityFactory _instance = null;
   
   protected CredentialIdentityFactory()
   { 
   }
   
   public static CredentialIdentityFactory getInstance()
   {
      if(_instance == null)
         _instance = new CredentialIdentityFactory();
      return _instance;
   }
   
   public static CredentialIdentity<Object> createIdentity(final Principal principal, 
         final Object cred)
   {
      return createIdentity(principal,cred, null);
   }
   
   public static CredentialIdentity<Object> createIdentity(final Principal principal, 
         final Object cred, final Role roles)
   {
      return new CredentialIdentity<Object>()
      {
         private static final long serialVersionUID = 1L;

         public Object getCredential()
         {
            return cred;
         }

         public void setCredential(Object credential)
         {   
         }

         public Group asGroup()
         { 
            return null;
         }
         
         public Principal asPrincipal()
         {
            return principal;
         }

         public String getName()
         { 
            return principal.getName();
         }

         public Role getRole()
         {
            return roles;
         }

         @Override
         public String toString()
         {
            StringBuilder builder = new StringBuilder();
            builder.append("CredentialIdentity[principal=").append(principal);
            builder.append(";roles=").append(roles).append("]");
            return builder.toString();
         } 
      }; 
   } 
}