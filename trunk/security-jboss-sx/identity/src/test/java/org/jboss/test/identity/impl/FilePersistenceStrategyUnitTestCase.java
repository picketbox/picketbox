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

import java.io.File;

import junit.framework.TestCase;

import org.jboss.security.identity.Identity;
import org.jboss.security.identity.Role;
import org.jboss.security.identity.plugins.FilePersistenceStrategy;
import org.jboss.security.identity.plugins.IdentityFactory;
import org.jboss.security.identity.plugins.PersistenceStrategy;
import org.jboss.security.identity.plugins.SimpleRole;

/**
 * A FilePersistenceStrategyUnitTestCase.
 * 
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @version $Revision: 1.1 $
 */
public class FilePersistenceStrategyUnitTestCase extends TestCase
{
   private static final String identityName = "test";

   private static final String path = System.getProperty("java.io.tmpdir");

   private static final File file = new File(path + File.separator + "test");

   private static final PersistenceStrategy ps = new FilePersistenceStrategy(path);

   public void testWriteIdentity() throws Exception
   {
      Identity identity = IdentityFactory.createIdentity(identityName);
      assertFalse("File already exists", file.exists());
      assertNotNull("Failed to persist", ps.persistIdentity(identity));
      assertTrue("File was not created", file.exists());
   }

   public void testReadIdentity() throws Exception
   {
      Identity identity = IdentityFactory.createIdentity(identityName);
      assertFalse("File already exists", file.exists());
      assertNotNull("Failed to persist", ps.persistIdentity(identity));
      assertTrue("File was not created", file.exists());

      Identity restored = ps.getIdentity(identityName);
      assertEquals("Objects are different", identity, restored);
   }

   public void testReadIdentityWithRole() throws Exception
   {
      Identity identity = IdentityFactory.createIdentityWithRole(identityName, "testRole");
      assertFalse("File already exists", file.exists());
      assertNotNull("Failed to persist", ps.persistIdentity(identity));
      assertTrue("File was not created", file.exists());

      Identity restored = ps.getIdentity(identityName);
      assertEquals("Objects are different", identity, restored);
      assertEquals("Role names are different", identity.getRole().getRoleName(), restored.getRole().getRoleName());
   }

   public void testReadIdentityWithRoleAndParent() throws Exception
   {
      Role parent = new SimpleRole("parent");
      Role role = new SimpleRole("testRole", parent);
      Identity identity = IdentityFactory.createIdentityWithRole(identityName, role);
      assertFalse("File already exists", file.exists());
      assertNotNull("Failed to persist", ps.persistIdentity(identity));
      assertTrue("File was not created", file.exists());

      Identity restored = ps.getIdentity(identityName);
      assertEquals("Objects are different", identity, restored);
      assertEquals("Role names are different", identity.getRole().getRoleName(), restored.getRole().getRoleName());
      assertEquals("Parent role names are different", identity.getRole().getParent().getRoleName(), restored.getRole()
            .getParent().getRoleName());
   }

   public void testRemoveIdentity() throws Exception
   {
      Identity identity = IdentityFactory.createIdentity(identityName);
      assertFalse("File already exists", file.exists());
      assertNotNull("Failed to persist", ps.persistIdentity(identity));
      assertTrue("File was not created", file.exists());

      assertTrue("Identity was not removed", ps.removeIdentity(identity));
   }

   public void testUpdateIdentityWithRole() throws Exception
   {
      Identity identity = IdentityFactory.createIdentity(identityName);
      assertFalse("File already exists", file.exists());
      assertNotNull("Failed to persist", ps.persistIdentity(identity));
      assertTrue("File was not created", file.exists());

      Identity restored = ps.getIdentity(identityName);
      assertEquals("Objects are different", identity, restored);
      assertNull("Role must be null", restored.getRole());

      identity = IdentityFactory.createIdentityWithRole(identityName, "testRole");
      ps.updateIdentity(identity);
      assertTrue("File was not re-created", file.exists());
      restored = ps.getIdentity(identityName);
      assertEquals("Objects are different", identity, restored);
      assertEquals("Role names are different", identity.getRole().getRoleName(), restored.getRole().getRoleName());
   }

   public void testWriteDuplicateIdentity() throws Exception
   {
      Identity identity = IdentityFactory.createIdentity(identityName);
      assertFalse("File already exists", file.exists());
      assertNotNull("Failed to persist", ps.persistIdentity(identity));
      assertTrue("File was not created", file.exists());

      Identity duplicate = IdentityFactory.createIdentity(identityName);
      assertNull("Should not persist duplicate Identity", ps.persistIdentity(duplicate));
   }

   @Override
   protected void tearDown() throws Exception
   {
      if (file.exists())
      {
         file.delete();
      }
   }

}
