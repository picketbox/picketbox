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
package org.jboss.security.identity.plugins;

import java.security.Principal;
import java.security.acl.Group;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;

import org.jboss.security.identity.Role;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.identity.RoleType;

//$Id$

/**
 *  Simple Role Group
 *  @author Anil.Saldhana@redhat.com
 *  @since  Nov 16, 2007 
 *  @version $Revision$
 */
public class SimpleRoleGroup extends SimpleRole implements RoleGroup
{
   private static final long serialVersionUID = 1L;

   private ArrayList<Role> roles = new ArrayList<Role>();

   private static final String ROLES_IDENTIFIER = "Roles";

   public SimpleRoleGroup(String roleName)
   {
      super(roleName);
   }

   public SimpleRoleGroup(String roleName, List<Role> roles)
   {
      super(roleName);
      addAll(roles);
   }

   public SimpleRoleGroup(Group rolesGroup)
   {
      super(rolesGroup.getName());
      Enumeration<? extends Principal> principals = rolesGroup.members();
      while (principals.hasMoreElements())
      {
         SimpleRole role = new SimpleRole(principals.nextElement().getName());
         addRole(role);
      }
   }

   public SimpleRoleGroup(Set<Principal> rolesAsPrincipals)
   {
      super(ROLES_IDENTIFIER);
      for (Principal p : rolesAsPrincipals)
      {
         SimpleRole role = new SimpleRole(p.getName());
         addRole(role);
      }
   }

   /*
    * (non-Javadoc)
    * @see org.jboss.security.identity.plugins.SimpleRole#getType()
    */
   @Override
   public RoleType getType()
   {
      return RoleType.group;
   }

   /*
    * (non-Javadoc)
    * @see org.jboss.security.identity.RoleGroup#addRole(org.jboss.security.identity.Role)
    */
   public synchronized void addRole(Role role)
   {
      if (!this.roles.contains(role))
         this.roles.add(role);
   }

   /*
    * (non-Javadoc)
    * @see org.jboss.security.identity.RoleGroup#addAll(java.util.List)
    */
   public synchronized void addAll(List<Role> roles)
   {
      if (roles != null)
      {
         for (Role role : roles)
         {
            if (!this.roles.contains(role))
            {
               this.roles.add(role);
            }
         }
      }
   }

   /*
    * (non-Javadoc)
    * @see org.jboss.security.identity.RoleGroup#removeRole(org.jboss.security.identity.Role)
    */
   public synchronized void removeRole(Role role)
   {
      this.roles.remove(role);
   }

   /*
    * (non-Javadoc)
    * @see org.jboss.security.identity.RoleGroup#clearRoles()
    */
   public synchronized void clearRoles()
   {
      this.roles.clear();
   }

   /*
    * (non-Javadoc)
    * @see org.jboss.security.identity.RoleGroup#getRoles()
    */
   public List<Role> getRoles()
   {
      // unmodifiable view: clients must update the roles through the addRole and removeRole methods.
      return Collections.unmodifiableList(roles);
   }

   /*
    * (non-Javadoc)
    * @see org.jboss.security.identity.plugins.SimpleRole#clone()
    */
   @SuppressWarnings("unchecked")
   public synchronized Object clone() throws CloneNotSupportedException
   {
      SimpleRoleGroup clone = (SimpleRoleGroup) super.clone();
      if (clone != null)
         clone.roles = (ArrayList<Role>) this.roles.clone();
      return clone;
   }

   /*
    * (non-Javadoc)
    * @see org.jboss.security.identity.plugins.SimpleRole#containsAll(org.jboss.security.identity.Role)
    */
   @Override
   public boolean containsAll(Role anotherRole)
   {
      boolean isContained = false;

      if (anotherRole.getType() == RoleType.simple)
      {
         // synchronize iteration to avoid concurrent modification exception.
         synchronized (this)
         {
            for (Role r : roles)
            {
               isContained = r.containsAll(anotherRole);
               if (isContained)
                  return true;
            }
         }
      }
      else
      {
         //Dealing with another roleGroup
         RoleGroup anotherRG = (RoleGroup) anotherRole;
         List<Role> anotherRoles = anotherRG.getRoles();
         for (Role r : anotherRoles)
         {
            //if any of the roles are not there, no point checking further
            if (!this.containsAll(r))
               return false;
         }
         return true;
      }
      return false;
   }

   /*
    * (non-Javadoc)
    * @see org.jboss.security.identity.RoleGroup#containsAtleastOneRole(org.jboss.security.identity.RoleGroup)
    */
   public boolean containsAtleastOneRole(RoleGroup anotherRole)
   {
      if (anotherRole == null)
         throw new IllegalArgumentException("anotherRole is null");
      List<Role> roleList = anotherRole.getRoles();
      for (Role r : roleList)
      {
         if (this.containsAll(r))
            return true;
      }
      return false;
   }

   /*
    * (non-Javadoc)
    * @see org.jboss.security.identity.RoleGroup#containsRole(org.jboss.security.identity.Role)
    */
   public synchronized boolean containsRole(Role role)
   {
      // synchronize iteration to avoid concurrent modification exception.
      for (Role r : roles)
      {
         if (r.containsAll(role))
            return true;
      }
      return false;
   }

   /*
    * (non-Javadoc)
    * @see org.jboss.security.identity.plugins.SimpleRole#toString()
    */
   @Override
   public String toString()
   {
      StringBuilder builder = new StringBuilder();
      builder.append(this.getRoleName());
      builder.append("(");
      synchronized (this)
      {
         for (Role role : roles)
         {
            builder.append(role.toString()).append(",");
         }
      }
      builder.append(")");
      return builder.toString();
   }
}