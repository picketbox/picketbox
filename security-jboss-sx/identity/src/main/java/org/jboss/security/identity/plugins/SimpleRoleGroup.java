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
      if (this.roles == null)
         this.roles = new ArrayList<Role>();
      this.roles.addAll(roles);
   }

   public SimpleRoleGroup(Group rolesGroup)
   {
      super(rolesGroup.getName());
      Enumeration<? extends Principal> principals = rolesGroup.members();
      while (principals.hasMoreElements())
      {
         roles.add(new SimpleRole(principals.nextElement().getName()));
      }
   }

   public SimpleRoleGroup(Set<Principal> rolesAsPrincipals)
   {
      super(ROLES_IDENTIFIER);
      for (Principal p : rolesAsPrincipals)
      {
         roles.add(new SimpleRole(p.getName()));
      }
   }

   @Override
   public RoleType getType()
   {
      return RoleType.group;
   }

   /**
    * @see RoleGroup#addRole(Role)
    */
   public void addRole(Role role)
   {
      this.roles.add(role);
   }

   /**
    * @see RoleGroup#removeRole(Role)
    */
   public void removeRole(Role role)
   {
      this.roles.remove(role);
   }

   /**
    * @see RoleGroup#clearRoles()
    */
   public void clearRoles()
   {
      this.roles.clear();
   }

   /**
    * @see RoleGroup#getRoles()
    */
   public List<Role> getRoles()
   {
      return roles;
   }

   @SuppressWarnings("unchecked")
   public synchronized Object clone() throws CloneNotSupportedException
   {
      SimpleRoleGroup clone = (SimpleRoleGroup) super.clone();
      if (clone != null)
         clone.roles = (ArrayList<Role>) this.roles.clone();
      return clone;
   }

   @Override
   public boolean containsAll(Role anotherRole)
   {
      boolean isContained = false;

      if (anotherRole.getType() == RoleType.simple)
      {
         for (Role r : roles)
         {
            isContained = r.containsAll(anotherRole);
            if (isContained)
               return true;
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

   /**
    * @see RoleGroup#containsAtleastOneRole(RoleGroup)
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

   /**
    * @see RoleGroup#containsRole(Role)
    */
   public boolean containsRole(Role role)
   {
      for (Role r : roles)
      {
         if (r.containsAll(role))
            return true;
      }
      return false;
   }

   @Override
   public String toString()
   {
      StringBuilder builder = new StringBuilder();
      builder.append(this.getRoleName());
      builder.append("(");
      for (Role role : roles)
      {
         builder.append(role.toString()).append(",");
      }
      builder.append(")");
      return builder.toString();
   }
}