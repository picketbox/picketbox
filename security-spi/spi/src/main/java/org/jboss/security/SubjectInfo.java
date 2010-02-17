/*
  * JBoss, Home of Professional Open Source
  * Copyright 2006, JBoss Inc., and individual contributors as indicated
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
package org.jboss.security;

import java.io.Serializable;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.Subject;

import org.jboss.security.identity.Identity;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.identity.extensions.CredentialIdentityFactory;


/**
 *  Holds information - principal, credential and subject
 *  This class is handled by the Util class associated with the security context
 *  @see SecurityContextUtil
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @since  Dec 26, 2006 
 *  @version $Revision$
 */
public class SubjectInfo implements Serializable
{ 
   private static final long serialVersionUID = 1L; 
   private Subject authenticatedSubject;
   
   private RoleGroup roles;
   
   private Set<Identity> identities;
   
   SubjectInfo(Principal principal, Object credential,Subject subject)
   { 
      this.addIdentity(CredentialIdentityFactory.createIdentity(principal, credential));
      this.authenticatedSubject = subject;
   }  
   
   /**
    * Create a SubjectInfo
    * @param identity
    * @param theSubject
    */
   SubjectInfo(Identity identity, Subject theSubject)
   {
      this.addIdentity(identity);
      this.authenticatedSubject = theSubject;
   }
   
   public Subject getAuthenticatedSubject()
   {
      return authenticatedSubject;
   }
   
   public void setAuthenticatedSubject(Subject authenticatedSubject)
   {
      this.authenticatedSubject = authenticatedSubject;
   }

   public RoleGroup getRoles()
   {
      return roles;
   }

   public void setRoles(RoleGroup roles)
   {
      this.roles = roles;
   } 
   
   public void addIdentity(Identity id)
   {
      if(identities == null)
         identities = new HashSet<Identity>();
      identities.add(id);   
   }
   
   @SuppressWarnings("unchecked")
   public <T> T getIdentity(Class<T> clazz)
   {
      if(this.identities != null)
      {
         for(Identity id:identities)
         {
            if(clazz.isAssignableFrom(id.getClass()))
               return (T) id; 
         }
      }
      return null;
   }
   
   public Set<Identity> getIdentities()
   {
      return this.identities;
   }
   
   public void setIdentities(Set<Identity> ids)
   {
      if(identities == null)
         identities = new HashSet<Identity>();
      identities.addAll(ids);
   }

   @Override
   public String toString()
   {
      StringBuilder builder = new StringBuilder(); 
      builder.append("Identities=" + this.identities);
      builder.append(" Subject=" + this.authenticatedSubject);
      builder.append(" Roles=" +  this.roles);
      return builder.toString();
   } 
} 