/*
 * JBoss, Home of Professional Open Source
 * Copyright 2005, JBoss Inc., and individual contributors as indicated
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
package org.jboss.test.security.acl;

import java.util.Arrays;

import junit.framework.TestCase;

import org.jboss.security.acl.ACL;
import org.jboss.security.acl.ACLEntry;
import org.jboss.security.acl.ACLEntryImpl;
import org.jboss.security.acl.ACLImpl;
import org.jboss.security.acl.ACLPermission;
import org.jboss.security.acl.BasicACLPermission;
import org.jboss.security.acl.CompositeACLPermission;
import org.jboss.security.identity.Identity;
import org.jboss.security.identity.plugins.IdentityFactory;

/**
 * <p>
 * This {@code TestCase} tests the functionality exposed by the {@code ACL} interface.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class ACLUnitTestCase extends TestCase
{
   private static final int ACL_SIZE = 5;

   private Identity[] identities;

   private ACLEntry[] entries;

   @Override
   protected void setUp() throws Exception
   {
      this.identities = new Identity[ACL_SIZE];
      for (int i = 0; i < ACL_SIZE; i++)
         this.identities[i] = IdentityFactory.createIdentity("Identity" + i);
      // create an entry with a basic permission.
      this.entries = new ACLEntryImpl[ACL_SIZE];
      this.entries[0] = new ACLEntryImpl(BasicACLPermission.READ, this.identities[0]);
      // build the remaining entries with composite permissions.
      this.entries[1] = new ACLEntryImpl(new CompositeACLPermission(), this.identities[1]);
      this.entries[2] = new ACLEntryImpl(new CompositeACLPermission(BasicACLPermission.READ), this.identities[2]);
      this.entries[3] = new ACLEntryImpl(new CompositeACLPermission(BasicACLPermission.CREATE,
            BasicACLPermission.UPDATE, BasicACLPermission.DELETE), this.identities[3]);
      this.entries[4] = new ACLEntryImpl(new CompositeACLPermission(BasicACLPermission.values()), this.identities[4]);
   }

   /**
    * <p>
    * Tests the execution of the {@code isGranted} method with different permissions and identities.
    * </p>
    * 
    * @throws Exception if an error occurs when running the test.
    */
   public void testIsGranted() throws Exception
   {
      // build the tested ACL.
      ACL acl = new ACLImpl(new TestResource(10), Arrays.asList(this.entries));
      assertEquals("Invalid number of entries", ACL_SIZE, acl.getEntries().size());

      // test the identity associated with a basic permission.
      assertTrue(acl.isGranted(BasicACLPermission.READ, this.identities[0]));
      assertFalse(acl.isGranted(BasicACLPermission.DELETE, this.identities[0]));
      assertFalse(acl.isGranted(new CompositeACLPermission(BasicACLPermission.CREATE, BasicACLPermission.UPDATE),
            this.identities[0]));

      // assert the empty permission is always granted.
      ACLPermission emptyPermission = new CompositeACLPermission();
      for (int i = 0; i < ACL_SIZE; i++)
         assertTrue(acl.isGranted(emptyPermission, this.identities[i]));

      // assert that identities[1] is only granted the empty permission.
      for (BasicACLPermission permission : BasicACLPermission.values())
         assertFalse(acl.isGranted(permission, this.identities[1]));
      assertFalse(acl.isGranted(new CompositeACLPermission(BasicACLPermission.values()), this.identities[1]));

      // test the identities associated to composite permissions.
      assertTrue(acl.isGranted(BasicACLPermission.READ, this.identities[2]));
      assertFalse(acl.isGranted(new CompositeACLPermission(BasicACLPermission.READ, BasicACLPermission.UPDATE),
            this.identities[2]));
      assertFalse(acl.isGranted(BasicACLPermission.CREATE, this.identities[2]));
      assertFalse(acl.isGranted(new CompositeACLPermission(BasicACLPermission.UPDATE, BasicACLPermission.DELETE),
            this.identities[2]));

      assertTrue(acl.isGranted(BasicACLPermission.CREATE, this.identities[3]));
      assertTrue(acl.isGranted(BasicACLPermission.UPDATE, this.identities[3]));
      assertTrue(acl.isGranted(new CompositeACLPermission(BasicACLPermission.CREATE, BasicACLPermission.DELETE),
            this.identities[3]));
      assertFalse(acl.isGranted(BasicACLPermission.READ, this.identities[3]));
      assertFalse(acl.isGranted(new CompositeACLPermission(BasicACLPermission.READ, BasicACLPermission.UPDATE),
            this.identities[3]));

      for (BasicACLPermission permission : BasicACLPermission.values())
         assertTrue(acl.isGranted(permission, this.identities[4]));
      assertTrue(acl.isGranted(new CompositeACLPermission(BasicACLPermission.READ), this.identities[4]));
      assertTrue(acl.isGranted(new CompositeACLPermission(BasicACLPermission.CREATE, BasicACLPermission.DELETE),
            this.identities[4]));
      assertTrue(acl.isGranted(new CompositeACLPermission(BasicACLPermission.CREATE, BasicACLPermission.UPDATE,
            BasicACLPermission.DELETE), this.identities[4]));
      assertTrue(acl.isGranted(new CompositeACLPermission(BasicACLPermission.values()), this.identities[4]));
   }
}
