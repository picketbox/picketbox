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
package org.jboss.test.identity.impl;

import junit.framework.TestCase;

import org.jboss.security.identity.Role;
import org.jboss.security.identity.plugins.SimpleRole;
import org.jboss.security.identity.plugins.SimpleRoleGroup;

//$Id$

/**
 *  Test complex RoleGroup situations
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jan 17, 2008 
 *  @version $Revision$
 */
public class RoleGroupUnitTestCase extends TestCase
{

   public void testAnybodyRole()
   {
      Role aRole = new SimpleRole("aRole");

      SimpleRoleGroup srg = new SimpleRoleGroup("Roles");
      srg.addRole(SimpleRole.ANYBODY_ROLE);
      assertTrue(srg.containsRole(aRole));
   }

   public void testNestedRoles()
   {
      SimpleRoleGroup srg = new SimpleRoleGroup("nested");
      srg.addRole(new SimpleRole("aRole"));
      srg.addRole(new SimpleRole("bRole"));

      SimpleRoleGroup methodRoles = new SimpleRoleGroup("Roles");
      methodRoles.addRole(srg);

      //Create user role now
      SimpleRoleGroup userRole = new SimpleRoleGroup("Roles");
      userRole.addRole(new SimpleRole("aRole"));
      methodRoles.containsAtleastOneRole(userRole);
   }

}
