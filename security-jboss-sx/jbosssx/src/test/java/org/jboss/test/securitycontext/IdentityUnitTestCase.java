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
package org.jboss.test.securitycontext;

import java.security.Principal;
import java.security.acl.Group;
import java.util.Set;

import junit.framework.TestCase;

import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextFactory;
import org.jboss.security.SecurityContextUtil;
import org.jboss.security.identity.Identity;
import org.jboss.security.identity.Role;
 
/**
 *  Identity in Security Context Unit Tests
 *  @author Anil.Saldhana@redhat.com
 *  @since  Feb 13, 2008 
 *  @version $Revision$
 */
public class IdentityUnitTestCase extends TestCase
{
   public void testSetIdentity() throws Exception
   {
      SecurityContext sc = SecurityContextFactory.createSecurityContext("Test");
      Identity i1 = new Identity1();
      Identity i2 = new Identity2();
      
      SecurityContextUtil util = sc.getUtil();
      
      util.addIdentity(i1);
      util.addIdentity(i2);
      
      Set<Identity> s1 = util.getIdentities(Identity1.class);
      Set<Identity> s2 = util.getIdentities(Identity2.class);
      
      assertEquals(1,s1.size());
      assertEquals(1,s2.size());
      assertTrue(s1.contains(i1));
      assertTrue(s2.contains(i2));
   }
   
   private class Identity1 implements Identity
   { 
      private static final long serialVersionUID = 1L;

      public Group asGroup()
      {
         return null;
      }

      public Principal asPrincipal()
      {
         return null;
      }

      public String getName()
      {
         return null;
      }

      public Role getRole()
      {
         return null;
      } 
   }
   
   private class Identity2 implements Identity
   {
      private static final long serialVersionUID = 1L;

      public Group asGroup()
      {
         return null;
      }

      public Principal asPrincipal()
      {
         return null;
      }

      public String getName()
      {
         return null;
      }

      public Role getRole()
      {
         return null;
      }      
   }
}