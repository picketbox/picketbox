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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Collection;

import junit.framework.TestCase;

import org.jboss.security.acl.ACL;
import org.jboss.security.acl.ACLEntry;
import org.jboss.security.acl.ACLEntryImpl;
import org.jboss.security.acl.ACLImpl;
import org.jboss.security.acl.ACLPersistenceStrategy;
import org.jboss.security.acl.BasicACLPermission;
import org.jboss.security.acl.JPAPersistenceStrategy;
import org.jboss.security.identity.plugins.IdentityFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * <p>
 * This {@code TestCase} tests the funcionality exposed by the {@code ACLProvider} 
 * interface
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class JPAStrategyUnitTestCase {
   private TestResource[] resources;

   private Collection<ACL> createdACLs;

   private ACLPersistenceStrategy strategy;

   @Before
   public void setUp() throws Exception
   {
      // create some test resources to be used by the tests.
      this.resources = new TestResource[10];
      for (int index = 0; index < this.resources.length; index++)
         this.resources[index] = new TestResource(index + 1);
      this.createdACLs = new ArrayList<ACL>();
      this.strategy = new JPAPersistenceStrategy(new TestResourceFactory());
   }

   @After
   public void tearDown() throws Exception
   {
      for (ACL acl : this.createdACLs)
         this.strategy.removeACL(acl);
   }

   /**
    * <p>
    * Tests the creation of ACLs for resources.
    * </p>
    * 
    * @throws Exception if an error occurs when running the test.
    */
   @Test
   public void testACLCreation() throws Exception
   {
      // assert no ACL exists for any of the resources.
      for (int index = 0; index < this.resources.length; index++)
         assertNull(this.strategy.getACL(this.resources[index]));

      // create ACLs for half of the resources.
      for (int index = 0; index < this.resources.length / 2; index++)
      {
         ACL acl = this.strategy.createACL(this.resources[index]);
         this.createdACLs.add(acl);
         assertNotNull(acl);
         assertEquals("Unexpected entries found", 0, acl.getEntries().size());
         assertEquals("Unexpected resource", this.resources[index], acl.getResource());
      }

      // assert no ACL still exists for the remaining resources.
      int index = (this.resources.length / 2) + 1;
      for (; index < this.resources.length; index++)
         assertNull(this.strategy.getACL(this.resources[index]));

      // assert that an ACL cannot be created for a null resource.
      boolean caughtException = false;
      try
      {
         this.strategy.createACL(null);
      }
      catch (IllegalArgumentException iae)
      {
         caughtException = true;
      }
      assertTrue("Expected exception not thrown", caughtException);
   }

   /**
    * <p>
    * Tests the update of existing ACLs.
    * </p>
    * 
    * @throws Exception if an error occurs when running the test.
    */
   @Test
   public void testACLUpdate() throws Exception
   {
      // create an empty ACL.
      ACL acl = this.strategy.createACL(this.resources[0]);
      this.createdACLs.add(acl);
      assertEquals("Unexpected entries found", 0, acl.getEntries().size());

      // add some entries to the ACL.
      int entriesNumber = 20;
      for (int i = 0; i < entriesNumber; i++)
      {
         ACLEntry entry = new ACLEntryImpl(BasicACLPermission.CREATE, IdentityFactory.createIdentity("Identity" + i));
         acl.addEntry(entry);
      }
      assertTrue("Failed to update the ACL", this.strategy.updateACL(acl));

      // retrieve the ACL again and check it has the added entries.
      acl = this.strategy.getACL(this.resources[0]);
      assertEquals("Invalid number of entries", entriesNumber, acl.getEntries().size());

      // now remove one of the entries.
      ACLEntry entry = acl.getEntries().iterator().next();
      acl.removeEntry(entry);
      assertTrue("Failed to update the ACL", this.strategy.updateACL(acl));

      // retrieve the ACL again and check it has one less entry.
      acl = this.strategy.getACL(this.resources[0]);
      assertEquals("Invalid number of entries", entriesNumber - 1, acl.getEntries().size());

      // assert that update fails for an ACL not managed by the strategy.
      Collection<ACLEntry> entries = new ArrayList<ACLEntry>();
      entries.add(new ACLEntryImpl(BasicACLPermission.UPDATE, IdentityFactory.createIdentity("Another Identity")));
      ACL otherACL = new ACLImpl(this.resources[1], entries);
      assertFalse(this.strategy.updateACL(otherACL));
   }

   /**
    * <p>
    * Tests the removal of existing ACLs.
    * </p>
    * 
    * @throws Exception if an error occurs when running the test.
    */
   @Test
   public void testACLRemoval() throws Exception
   {
      ACL[] acls = new ACL[this.resources.length];
      for (int index = 0; index < this.resources.length; index++)
      {
         acls[index] = this.strategy.createACL(this.resources[index]);
         this.createdACLs.add(acls[index]);
      }

      // remove some ACLs.
      for (int index = 0; index < this.resources.length / 2; index++)
      {
         assertTrue(this.strategy.removeACL(acls[index]));
         // assert no ACL is associated to the resources anymore.
         assertNull(this.strategy.getACL(this.resources[index]));
         // removing an ACL that is not managed anymore by the strategy must return false.
         assertFalse(this.strategy.removeACL(acls[index]));
      }

      // assert the remaining resources are still associated with an ACL.
      int index = (this.resources.length / 2) + 1;
      for (; index < this.resources.length; index++)
         assertNotNull(this.strategy.getACL(this.resources[index]));
   }

   /**
    * <p>
    * Tests the search functionality of the {@code JPAPersistenceStrategy} when a {@code ResourceFactory}
    * has been set.
    * </p>
    * 
    * @throws Exception if an error occurs when running the test.
    */
   @Test
   public void testStrategyWithResourceFactory() throws Exception
   {
      ACL[] acls = new ACL[this.resources.length];
      for (int index = 0; index < this.resources.length; index++)
      {
         acls[index] = this.strategy.createACL(this.resources[index]);
         this.createdACLs.add(acls[index]);
      }

      // retrieves all persisted ACLs.
      Collection<ACL> retrievedACLs = this.strategy.getACLs();
      assertNotNull(retrievedACLs);

      // assert all retrieved ACLs had their resource correctly set by the factory.
      for (ACL acl : retrievedACLs)
         assertNotNull(acl.getResource());
   }
}
