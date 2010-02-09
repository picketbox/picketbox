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
import org.jboss.security.identity.RoleFactory;
import org.jboss.security.identity.plugins.SimpleRole;
import org.jboss.security.identity.plugins.SimpleRoleGroup;

//$Id$

/**
 *  Tests for the Role classes
 *  @author Anil.Saldhana@redhat.com
 *  @since  Dec 20, 2007 
 *  @version $Revision$
 */
public class RoleUnitTestCase extends TestCase
{
   public void testRoleFactory() throws Exception
   {
      assertTrue(RoleFactory.createRole("myRole") instanceof SimpleRole);
      assertTrue(RoleFactory.createRoleGroup("myRoleGroup") instanceof SimpleRoleGroup);
   }

   public void testSimpleRoleContains() throws Exception
   {
      Role firstRole = new SimpleRole("A");
      Role secondRole = new SimpleRole("B");

      assertTrue(firstRole.containsAll(firstRole));
      assertFalse(firstRole.containsAll(secondRole));
      assertFalse(secondRole.containsAll(firstRole));
   }

   public void testSimpleRoleGroupContains() throws Exception
   {
      SimpleRoleGroup firstRoleGroup = new SimpleRoleGroup("firstrg");
      firstRoleGroup.getRoles().add(new SimpleRole("A"));
      firstRoleGroup.getRoles().add(new SimpleRole("B"));
      firstRoleGroup.getRoles().add(new SimpleRole("C"));

      SimpleRoleGroup secondRoleGroup = new SimpleRoleGroup("secondrg");
      secondRoleGroup.getRoles().add(new SimpleRole("A"));
      secondRoleGroup.getRoles().add(new SimpleRole("B"));

      assertTrue(firstRoleGroup.containsAll(firstRoleGroup));
      assertTrue(secondRoleGroup.containsAll(secondRoleGroup));
      assertTrue(firstRoleGroup.containsAll(secondRoleGroup));
      assertFalse(secondRoleGroup.containsAll(firstRoleGroup));

      assertTrue(firstRoleGroup.containsAtleastOneRole(secondRoleGroup));
      assertTrue(secondRoleGroup.containsAtleastOneRole(firstRoleGroup));
   }

   public void testSimpleRoleGroup()
   {
      SimpleRoleGroup srg = new SimpleRoleGroup("Roles");
      srg.addRole(new SimpleRole("aRole"));
      assertTrue(srg.containsAll(new SimpleRole("aRole")));
   }
}
