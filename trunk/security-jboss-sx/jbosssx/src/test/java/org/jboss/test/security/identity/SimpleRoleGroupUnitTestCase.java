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
package org.jboss.test.security.identity;

import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

import junit.framework.TestCase;

import org.jboss.security.SimplePrincipal;
import org.jboss.security.identity.plugins.SimpleRoleGroup;

//$Id$

/**
 *  Test the SimpleRoleGroup implementation for JBossSX
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jan 8, 2008 
 *  @version $Revision$
 */
public class SimpleRoleGroupUnitTestCase extends TestCase
{
   public void testCtrWithPrincipalSet()
   {
      Set<Principal> principalSet = new HashSet<Principal>();
      principalSet.add(new SimplePrincipal("aRole"));
      
      SimpleRoleGroup sr = new SimpleRoleGroup(principalSet);
      assertNotNull(sr);
      assertEquals("aRole",sr.getRoles().get(0).getRoleName());
   }
}