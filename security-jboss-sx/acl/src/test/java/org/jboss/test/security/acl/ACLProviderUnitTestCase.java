/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2008, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors. 
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
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;
import org.jboss.security.acl.ACLEntry;
import org.jboss.security.acl.ACLEntryImpl;
import org.jboss.security.acl.ACLPersistenceStrategy;
import org.jboss.security.acl.ACLProvider;
import org.jboss.security.acl.ACLProviderImpl;
import org.jboss.security.acl.ACLRegistration;
import org.jboss.security.acl.BasicACLPermission;
import org.jboss.security.acl.CompositeACLPermission;
import org.jboss.security.acl.EntitlementEntry;
import org.jboss.security.acl.JPAPersistenceStrategy;
import org.jboss.security.authorization.Resource;
import org.jboss.security.authorization.ResourceKeys;
import org.jboss.security.identity.Identity;
import org.jboss.security.identity.plugins.IdentityFactory;

/**
 * <p>
 * This {@code TestCase} tests the functionality implemented by the {@code ACLProviderImpl} class.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class ACLProviderUnitTestCase extends TestCase
{

   private Resource[] resources;

   private Identity identity;

   private final ACLRegistration registration;

   private final ACLProvider provider;

   /**
    * <p>
    * Default constructor. Initializes the state of this {@code TestCase}.
    * </p>
    */
   public ACLProviderUnitTestCase()
   {
      ACLPersistenceStrategy strategy = new JPAPersistenceStrategy();
      this.registration = new TestACLRegistration(strategy);
      this.provider = new ACLProviderImpl();
      provider.setPersistenceStrategy(strategy);

   }

   /*
    * (non-Javadoc)
    * 
    * @see junit.framework.TestCase#setUp()
    */
   @Override
   public void setUp() throws Exception
   {
      // =================================== IDENTITY ============================= //
      this.identity = IdentityFactory.createIdentity("Test Identity");

      // =================================== RESOURCES ============================= //
      this.resources = new Resource[10];
      for (int i = 0; i < resources.length; i++)
         resources[i] = new TestResource(i, "Resource " + i);

      // create the relationships between the resources.
      Collection<Resource> childResources = new ArrayList<Resource>();
      // resource 0 has resource 1 as child.
      childResources.add(resources[1]);
      resources[0].getMap().put(ResourceKeys.CHILD_RESOURCES, childResources);
      resources[1].getMap().put(ResourceKeys.PARENT_RESOURCE, resources[0]);
      // resource 1 has resource 2 as child.
      childResources = new ArrayList<Resource>();
      childResources.add(resources[2]);
      resources[1].getMap().put(ResourceKeys.CHILD_RESOURCES, childResources);
      resources[2].getMap().put(ResourceKeys.PARENT_RESOURCE, resources[1]);
      // resource 2 has resources 3, 4 and 5 as children.
      childResources = new ArrayList<Resource>();
      childResources.add(resources[3]);
      childResources.add(resources[4]);
      childResources.add(resources[5]);
      resources[2].getMap().put(ResourceKeys.CHILD_RESOURCES, childResources);
      resources[3].getMap().put(ResourceKeys.PARENT_RESOURCE, resources[2]);
      resources[4].getMap().put(ResourceKeys.PARENT_RESOURCE, resources[2]);
      resources[5].getMap().put(ResourceKeys.PARENT_RESOURCE, resources[2]);
      // resource 4 has resources 6 and 7 as children.
      childResources = new ArrayList<Resource>();
      childResources.add(resources[6]);
      childResources.add(resources[7]);
      resources[4].getMap().put(ResourceKeys.CHILD_RESOURCES, childResources);
      resources[6].getMap().put(ResourceKeys.PARENT_RESOURCE, resources[4]);
      resources[7].getMap().put(ResourceKeys.PARENT_RESOURCE, resources[4]);
      // resource 5 has resources 8 and 9 as children.
      childResources = new ArrayList<Resource>();
      childResources.add(resources[8]);
      childResources.add(resources[9]);
      resources[5].getMap().put(ResourceKeys.CHILD_RESOURCES, childResources);
      resources[8].getMap().put(ResourceKeys.PARENT_RESOURCE, resources[5]);
      resources[9].getMap().put(ResourceKeys.PARENT_RESOURCE, resources[5]);

      // =================================== ACLs ============================= //

      // register an ACL with the resource 0 - identity has all permissions here.
      Collection<ACLEntry> entries = new ArrayList<ACLEntry>();
      entries.add(new ACLEntryImpl(new CompositeACLPermission(BasicACLPermission.values()), this.identity));
      registration.registerACL(this.resources[0], entries);

      // register an ACL with the resource 4 - identity has read and update permissions.
      entries = new ArrayList<ACLEntry>();
      entries.add(new ACLEntryImpl(new CompositeACLPermission(BasicACLPermission.READ, BasicACLPermission.UPDATE),
            this.identity));
      registration.registerACL(this.resources[4], entries);

      // register an ACL with the resource 5 - identity has create, read and delete permissions.
      entries = new ArrayList<ACLEntry>();
      entries.add(new ACLEntryImpl(new CompositeACLPermission(BasicACLPermission.CREATE, BasicACLPermission.READ,
            BasicACLPermission.DELETE), this.identity));
      registration.registerACL(this.resources[5], entries);

      // register an ACL with the resource 7 - identity has no corresponding entry (no permissions).
      entries = new ArrayList<ACLEntry>();
      entries.add(new ACLEntryImpl(new CompositeACLPermission(BasicACLPermission.values()), IdentityFactory
            .createIdentity("Another Identity")));
      registration.registerACL(this.resources[7], entries);

      // register an ACL with the resource 9 - identity has only read permission.
      entries = new ArrayList<ACLEntry>();
      entries.add(new ACLEntryImpl(new CompositeACLPermission(BasicACLPermission.READ), this.identity));
      registration.registerACL(this.resources[9], entries);
   }

   @Override
   protected void tearDown() throws Exception {
      // deregisters the ACLs.
      for (Resource resource : this.resources) { this.registration.deRegisterACL(resource); }
   }

   /**
    * <p>
    * Tests the behavior of the {@code getEntitlements} method.
    * </p>
    * 
    * @throws Exception if an error occurs while running the test.
    */
   public void testGetEntitlements() throws Exception
   {
      Set<EntitlementEntry> entries = this.provider.getEntitlements(EntitlementEntry.class, this.resources[2],
            this.identity);
      assertNotNull(entries);
      // we expect 7 entries, corresponding to resources 2, 3, 4, 5, 6, 8 and 9.
      assertEquals("Found unexpected number of entries", 7, entries.size());

      // organize the entries according to their resource id so we can check the contents of each expected entry.
      Map<Integer, EntitlementEntry> entriesMap = new HashMap<Integer, EntitlementEntry>();
      for (EntitlementEntry entry : entries)
      {
         TestResource resource = (TestResource) entry.getResource();
         entriesMap.put(resource.getResourceId(), entry);
      }

      // identity should have create, update, read and delete permissions over resources 2 and 3.
      EntitlementEntry entry = entriesMap.get(2);
      assertNotNull(entry);
      CompositeACLPermission expectedPermission = new CompositeACLPermission(BasicACLPermission.values());
      assertEquals("Found unexpected permissions", expectedPermission, entry.getPermission());
      entry = entriesMap.get(3);
      assertNotNull(entry);
      assertEquals("Found unexpected permissions", expectedPermission, entry.getPermission());

      // identity should have read and update permissions over resources 4 and 6.
      entry = entriesMap.get(4);
      assertNotNull(entry);
      expectedPermission = new CompositeACLPermission(BasicACLPermission.READ, BasicACLPermission.UPDATE);
      assertEquals("Found unexpected permissions", expectedPermission, entry.getPermission());
      entry = entriesMap.get(6);
      assertNotNull(entry);
      assertEquals("Found unexpected permissions", expectedPermission, entry.getPermission());

      // identity should have create, read and delete permissions over resources 5 and 8.
      entry = entriesMap.get(5);
      assertNotNull(entry);
      expectedPermission = new CompositeACLPermission(BasicACLPermission.CREATE, BasicACLPermission.READ,
            BasicACLPermission.DELETE);
      assertEquals("Found unexpected permissions", expectedPermission, entry.getPermission());
      entry = entriesMap.get(8);
      assertNotNull(entry);
      assertEquals("Found unexpected permissions", expectedPermission, entry.getPermission());

      // identity should have read permission over resource 9.
      entry = entriesMap.get(9);
      assertNotNull(entry);
      expectedPermission = new CompositeACLPermission(BasicACLPermission.READ);
      assertEquals("Found unexpected permissions", expectedPermission, entry.getPermission());

   }
}
