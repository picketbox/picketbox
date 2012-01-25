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

import java.util.ArrayList;
import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.EntityTransaction;
import javax.persistence.Persistence;

import junit.framework.TestCase;

import org.jboss.security.acl.ACL;
import org.jboss.security.acl.ACLEntry;
import org.jboss.security.acl.ACLEntryImpl;
import org.jboss.security.acl.ACLImpl;
import org.jboss.security.acl.BasicACLPermission;
import org.jboss.security.acl.CompositeACLPermission;
import org.jboss.security.acl.Util;
import org.jboss.security.identity.plugins.IdentityFactory;

/**
 * <p>
 * This {@code TestCase} tests the functionality of the persistence layer added to the {@code ACL} implementation
 * classes. It uses an in-memory hsql test database, so there is no need to perform any special database cleanup in case
 * one of the tests fail. Every time the tests are run a clean new database is used.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class PersistenceTestCase extends TestCase
{
   private EntityManagerFactory entityManagerFactory;

   private EntityManager entityManager;

   private List<ACLEntryImpl> persistedEntries;

   private List<ACLImpl> persistedACLs;

   /*
    * (non-Javadoc)
    * 
    * @see junit.framework.TestCase#setUp()
    */
   @Override
   protected void setUp() throws Exception
   {
      this.entityManagerFactory = Persistence.createEntityManagerFactory("ACL");
      this.entityManager = entityManagerFactory.createEntityManager();
      this.persistedACLs = new ArrayList<ACLImpl>();
      this.persistedEntries = new ArrayList<ACLEntryImpl>();

      // create the test entries.
      this.persistedEntries
            .add(new ACLEntryImpl(BasicACLPermission.READ, IdentityFactory.createIdentity("Identity-1")));
      this.persistedEntries.add(new ACLEntryImpl(new CompositeACLPermission(BasicACLPermission.CREATE,
            BasicACLPermission.READ), IdentityFactory.createIdentity("Identity-2")));
      this.persistedEntries.add(new ACLEntryImpl(new CompositeACLPermission(BasicACLPermission.values()),
            IdentityFactory.createIdentity("Identity-3")));

      // create the test acls.
      this.persistedACLs.add(new ACLImpl(new TestResource(100, "Resource-1")));
      this.persistedACLs.add(new ACLImpl(new TestResource(200, "Resource-2"), new ArrayList<ACLEntry>(
            this.persistedEntries)));

      // persist everything.
      for (ACL acl : this.persistedACLs)
         this.persistEntity(acl);
   }

   /*
    * (non-Javadoc)
    * 
    * @see junit.framework.TestCase#tearDown()
    */
   @Override
   protected void tearDown() throws Exception
   {
      // remove the persisted entities - removing the acl also removes the entries.
      for (ACLImpl acl : this.persistedACLs)
      {
         // re-attach the acl before removing.
         ACLImpl attachedACL = this.entityManager.find(ACLImpl.class, acl.getACLId());
         this.removeEntity(attachedACL);
      }

      // assert the acls have been removed.
      for (ACLImpl acl : this.persistedACLs)
         assertNull(this.entityManager.find(ACLImpl.class, acl.getACLId()));

      // assert the entries have been also removed.
      for (ACLEntryImpl entry : this.persistedEntries)
         assertNull(this.entityManager.find(ACLEntryImpl.class, entry.getACLEntryId()));

      if (this.entityManager != null)
         entityManager.close();
      this.entityManagerFactory.close();
   }

   /**
    * <p>
    * Tests persisting the {@code ACLEntry} objects to a database.
    * </p>
    * 
    * @throws Exception if an error occurs when running the test.
    */
   public void testPersistACLEntry() throws Exception
   {
      // assert the entries have been created by checking if the auto-generated id has been set on each entry.
      assertTrue("Entry1 id value has not been generated", this.persistedEntries.get(0).getACLEntryId() > 0);
      assertTrue("Entry2 id value has not been generated", this.persistedEntries.get(1).getACLEntryId() > 0);
      assertTrue("Entry3 id value has not been generated", this.persistedEntries.get(2).getACLEntryId() > 0);

   }

   /**
    * <p>
    * Tests searching for the persisted {@code ACLEntry} objects.
    * </p>
    * 
    * @throws Exception if an error occurs when running the test.
    */
   public void testSearchACLEntry() throws Exception
   {
      // clear the entity manager so that it goes to the database when searching for entries.
      this.entityManager.clear();

      // load the entries from the database using their primary key and validate them.
      for (ACLEntryImpl entry : this.persistedEntries)
      {
         ACLEntryImpl loadedEntry = this.entityManager.find(ACLEntryImpl.class, entry.getACLEntryId());
         assertNotNull("Entry could not be retrieved by primary key", loadedEntry);
         assertEquals(entry, loadedEntry);
      }

      // execute some queries and validate the results.
      ACLEntryImpl entry = this.persistedEntries.get(1);
      ACLEntryImpl queryResult = (ACLEntryImpl) this.entityManager.createQuery(
            "SELECT e FROM ACLEntryImpl e WHERE e.identityOrRole LIKE '"
                  + entry.getIdentityOrRole() + "'").getSingleResult();
      assertNotNull("Entry2 could not be retrieved by it's identity", queryResult);
      assertEquals(entry, queryResult);

      entry = this.persistedEntries.get(0);
      queryResult = (ACLEntryImpl) this.entityManager.createQuery(
            "SELECT e FROM ACLEntryImpl e WHERE e.bitMask = " + BasicACLPermission.READ.getMaskValue())
            .getSingleResult();
      assertNotNull("Entry1 could not be retrieved by it's bitmask value", queryResult);
      assertEquals(entry, queryResult);
   }

   /**
    * <p>
    * Tests persisting the {@code ACL} objects to a database.
    * </p>
    * 
    * @throws Exception if an error occurs when running the test.
    */
   public void testPersistACL() throws Exception
   {
      // assert the ACLs and their associated entries have been persisted
      for (ACLImpl acl : this.persistedACLs)
      {
         assertTrue("ACL id value has not been generated", acl.getACLId() > 0);
         for (ACLEntry entry : acl.getEntries())
            assertTrue("ACL entry has not been persisted", ((ACLEntryImpl) entry).getACLEntryId() > 0);
      }
   }

   /**
    * <p>
    * Tests searching for the persisted {@code ACL} objects.
    * </p>
    * 
    * @throws Exception if an error occurs when running the test.
    */
   public void testSearchACL() throws Exception
   {
      // clear the entity manager's cache.
      this.entityManager.clear();

      // load the ACLs from the database using their primary key and validate them.
      ACLImpl loadedACL1 = this.entityManager.find(ACLImpl.class, this.persistedACLs.get(0).getACLId());
      assertNotNull("ACL1 could not be retrieved", loadedACL1);
      assertEquals("Loaded ACL contains unexpected number of entries", 0, loadedACL1.getEntries().size());
      assertNull(loadedACL1.getResource());

      ACLImpl loadedACL2 = this.entityManager.find(ACLImpl.class, this.persistedACLs.get(1).getACLId());
      assertNotNull("ACL2 could not be retrieved", loadedACL2);
      assertEquals("Loaded ACL contains unexpected number of entries", 3, loadedACL2.getEntries().size());
      assertTrue(loadedACL2.getEntries().contains(this.persistedEntries.get(0)));
      assertTrue(loadedACL2.getEntries().contains(this.persistedEntries.get(1)));
      assertTrue(loadedACL2.getEntries().contains(this.persistedEntries.get(2)));
      assertNull(loadedACL2.getResource());

      // find the ACLs using the resource and validate the result.
      ACLImpl acl = this.persistedACLs.get(0);
      ACLImpl queryResult = (ACLImpl) this.entityManager.createQuery(
            "SELECT a FROM ACLImpl a WHERE a.resourceAsString LIKE '" + Util.getResourceAsString(acl.getResource())
                  + "'").getSingleResult();
      assertNotNull("ACL1 could not be retrieved by it's resource", queryResult);
      assertEquals("Queried ACL id does not match the expected id", acl.getACLId(), queryResult.getACLId());
      assertEquals("Queried ACL contains unexpected number of entries", 0, queryResult.getEntries().size());

      acl = this.persistedACLs.get(1);
      queryResult = (ACLImpl) this.entityManager.createQuery(
            "SELECT a FROM ACLImpl a WHERE a.resourceAsString LIKE '" + Util.getResourceAsString(acl.getResource())
                  + "'").getSingleResult();
      assertNotNull("ACL2 could not be retrieved by it's resource", queryResult);
      assertEquals("Queried ACL id does not match the expected id", acl.getACLId(), queryResult.getACLId());
      assertEquals("Queried ACL contains unexpected number of entries", 3, queryResult.getEntries().size());
      assertTrue(queryResult.getEntries().contains(this.persistedEntries.get(0)));
      assertTrue(queryResult.getEntries().contains(this.persistedEntries.get(1)));
      assertTrue(queryResult.getEntries().contains(this.persistedEntries.get(2)));

   }

   /**
    * <p>
    * Tests updating the persisted {@code ACL} objects.
    * </p>
    * 
    * @throws Exception if an error occurs when running the test.
    */
   public void testUpdateACL() throws Exception
   {
      // add some entries to the acls and remove one of the existing entries from ACL2.
      ACLEntryImpl entry4 = new ACLEntryImpl(BasicACLPermission.CREATE, IdentityFactory.createIdentity("Identity-4"));
      ACLEntryImpl entry5 = new ACLEntryImpl(new CompositeACLPermission(BasicACLPermission.CREATE,
            BasicACLPermission.DELETE), IdentityFactory.createIdentity("Identity-5"));
      ACLEntryImpl entry6 = new ACLEntryImpl(new CompositeACLPermission(BasicACLPermission.values()), IdentityFactory
            .createIdentity("Identity-6"));

      ACLImpl acl1 = null;
      ACLImpl acl2 = null;
      EntityTransaction transaction = this.entityManager.getTransaction();
      transaction.begin();
      try
      {
         acl1 = this.entityManager.merge(this.persistedACLs.get(0));
         acl1.addEntry(entry4);
         acl1.addEntry(entry5);

         acl2 = this.entityManager.merge(this.persistedACLs.get(1));
         acl2.addEntry(entry6);
         acl2.removeEntry(this.persistedEntries.get(0));
         transaction.commit();
      }
      catch (RuntimeException re)
      {
         re.printStackTrace();
         transaction.rollback();
      }

      // add the new entries to the persisted entries collection.
      this.persistedEntries.add(entry4);
      this.persistedEntries.add(entry5);
      this.persistedEntries.add(entry6);

      // clear the entity manager's cache.
      this.entityManager.clear();

      // load the ACLs again and validate the changes.
      ACLImpl loadedACL1 = this.entityManager.find(ACLImpl.class, acl1.getACLId());
      assertNotNull("ACL1 could not be retrieved", loadedACL1);
      assertEquals("Loaded ACL contains unexpected number of entries", 2, loadedACL1.getEntries().size());
      assertTrue(loadedACL1.getEntries().contains(entry4));
      assertTrue(loadedACL1.getEntries().contains(entry5));

      ACLImpl loadedACL2 = this.entityManager.find(ACLImpl.class, acl2.getACLId());
      assertNotNull("ACL2 could not be retrieved", loadedACL2);
      assertEquals("Loaded AC2 contains unexpected number of entries", 3, loadedACL2.getEntries().size());
      assertFalse(loadedACL2.getEntries().contains(this.persistedEntries.get(0)));
      assertTrue(loadedACL2.getEntries().contains(this.persistedEntries.get(1)));
      assertTrue(loadedACL2.getEntries().contains(this.persistedEntries.get(2)));
      assertTrue(loadedACL2.getEntries().contains(entry6));
   }

   /**
    * <p>
    * Persists the specified entity to the database.
    * </p>
    * 
    * @param entity an {@code Object} representing the entity to be persisted.
    */
   private void persistEntity(Object entity)
   {
      EntityTransaction transaction = this.entityManager.getTransaction();
      transaction.begin();
      try
      {
         this.entityManager.persist(entity);
         transaction.commit();
      }
      catch (RuntimeException re)
      {
         re.printStackTrace();
         transaction.rollback();
      }
   }

   /**
    * <p>
    * Removes the specified entity from the database.
    * </p>
    * 
    * @param entity an {@code Object} representing the entity to be removed.
    */
   private void removeEntity(Object entity)
   {
      EntityTransaction transaction = this.entityManager.getTransaction();
      transaction.begin();
      try
      {
         this.entityManager.remove(entity);
         transaction.commit();
      }
      catch (RuntimeException re)
      {
         re.printStackTrace();
         transaction.rollback();
      }
   }
}
