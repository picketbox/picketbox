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

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Arrays;

import org.jboss.security.identity.Role;

import junit.framework.TestCase;

/**
 * Tests for SimpleRoleGroup.
 *
 * @author philippe.marschall@gmail.com
 *  @since  Jun 10, 2015
 *  @version $Revision$
 *
 */
public class SimpleRoleGroupUnitTestCase extends TestCase
{

   /**
    * Verifies old serialized objects and still be read in correctly.
    * @throws IOException if this test fails
    * @throws ClassNotFoundException if this test fails
    */
   public void testReadOldObject() throws IOException, ClassNotFoundException
   {
      SimpleRoleGroup group = readGroup();
      assertEquals("role name", "testCopyNewObject", group.getRoleName());
      assertEquals("number of roles", 2, group.getRoles().size());
      assertTrue("contains \"role1\"", group.getRoles().contains(new SimpleRole("role1")));
      assertTrue("contains \"role2\"", group.getRoles().contains(new SimpleRole("role2")));
   }

   private static SimpleRoleGroup readGroup() throws IOException, ClassNotFoundException
   {
      FileInputStream fis = new FileInputStream("src/test/resources/org/jboss/security/identity/plugins/SimpleRoleGroup.ser");
      try
      {
         ObjectInputStream ois = new ObjectInputStream(new BufferedInputStream(fis));
         try
         {
            return (SimpleRoleGroup) ois.readObject();
         } finally
         {
            ois.close();
         }
      }
      finally
      {
         fis.close();
      }
   }

   /**
    * Verifies serialization and deserialization works correctly for the
    * current implemenation of SimpleRoleGroup.
    *
    * @throws ClassNotFoundException if this test fails
    * @throws IOException if this test fails
    */
   public void testCopyNewObject() throws ClassNotFoundException, IOException
   {
      SimpleRoleGroup group = new SimpleRoleGroup("testCopyNewObject");
      group.addAll(Arrays.<Role>asList(new SimpleRole("role1"), new SimpleRole("role2")));

      SimpleRoleGroup copy = copy(group);
      assertEquals("role name", "testCopyNewObject", copy.getRoleName());
      assertEquals("number of roles", 2, copy.getRoles().size());
      assertTrue("contains \"role1\"", copy.getRoles().contains(new SimpleRole("role1")));
      assertTrue("contains \"role2\"", copy.getRoles().contains(new SimpleRole("role2")));
   }

   private static SimpleRoleGroup copy(SimpleRoleGroup toCopy) throws IOException, ClassNotFoundException
   {
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      ObjectOutputStream oos = new ObjectOutputStream(bos);
      try
      {
         oos.writeObject(toCopy);
      }
      finally
      {
         oos.close();
      }
      ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray()));
      return (SimpleRoleGroup) ois.readObject();
   }

}
