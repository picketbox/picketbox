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
import java.util.Collection;
import java.util.List;

import junit.framework.TestCase;

import org.jboss.security.acl.ACLEntry;
import org.jboss.security.acl.ACLEntryImpl;
import org.jboss.security.acl.ACLPersistenceStrategy;
import org.jboss.security.acl.ACLProvider;
import org.jboss.security.acl.ACLProviderImpl;
import org.jboss.security.acl.ACLRegistration;
import org.jboss.security.acl.BasicACLPermission;
import org.jboss.security.acl.BitMaskPermission;
import org.jboss.security.acl.CompositeACLPermission;
import org.jboss.security.acl.JPAPersistenceStrategy;
import org.jboss.security.authorization.AuthorizationException;
import org.jboss.security.authorization.Resource;
import org.jboss.security.identity.Identity;
import org.jboss.security.identity.plugins.IdentityFactory;

/**
 * <p>
 * This {@code TestCase} tests some ACL use cases.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class ACLUseTestCase extends TestCase
{
   private static int TOTAL_RESOURCES = 5000;

   private static final int TOTAL_IDENTITIES = 50;

   private TestResource[] resources;

   private Identity[] identities;

   private ACLPersistenceStrategy strategy;

   private ACLRegistration registration;

   private ACLProvider provider;

   @Override
   protected void setUp() throws Exception
   {
      //Get it as a system property to the test (eg. maven profiles)
      String resourcesCount = System.getProperty("acl.resources","100");
      TOTAL_RESOURCES = Integer.parseInt(resourcesCount); 
         
      this.strategy = new JPAPersistenceStrategy();
      this.registration = new TestACLRegistration(strategy);
      this.provider = new ACLProviderImpl();
      this.provider.setPersistenceStrategy(strategy);

      // create the resources used in the tests.
      this.resources = new TestResource[TOTAL_RESOURCES];
      for (int i = 0; i < TOTAL_RESOURCES; i++)
         this.resources[i] = new TestResource(i, "Resource" + i);

      // create the identities used in the tests.
      this.identities = new Identity[TOTAL_IDENTITIES];
      for (int i = 0; i < TOTAL_IDENTITIES; i++)
         this.identities[i] = IdentityFactory.createIdentity("Identity" + i);

      BitMaskPermission readPermission = BasicACLPermission.READ;
      BitMaskPermission noPermission = new CompositeACLPermission();
      BitMaskPermission allPermission = new CompositeACLPermission(BasicACLPermission.values());

      // register the ACLs for the resources used by the tests.
      for (int i = 0; i < TOTAL_RESOURCES; i++)
      {
         Collection<ACLEntry> entries = new ArrayList<ACLEntry>();
         // add the entries ("even" identities can read "even" resources)
         for (int j = 0; j < TOTAL_IDENTITIES; j++)
         {
            if ((i + j) % 2 == 0)
            {
               // let some identities have all permissions.
               if (j % 5 == 0)
                  entries.add(new ACLEntryImpl(allPermission, this.identities[j]));
               else
                  entries.add(new ACLEntryImpl(readPermission, this.identities[j]));
            }
            else
            {
               entries.add(new ACLEntryImpl(noPermission, this.identities[j]));
            }
         }
         this.registration.registerACL(this.resources[i], entries);
      }
   }

   @Override
   protected void tearDown() throws Exception
   {
      // deregisters the ACLs.
      for (Resource resource : this.resources)
         this.registration.deRegisterACL(resource);
   }

   /**
    * <p>
    * Tests the use of ACLs in different use cases, such as filtering, updating and removing
    * resources protected by an ACL.
    * </p>
    * 
    * @throws Exception if an error occurs when running the test.
    */
   public void testACLUseCases() throws Exception
   {
      // we start by filtering the resources by the identity.
      Identity identity = this.identities[0];
      TestResource[] filteredResources = this.filterResources(identity);
      assertEquals("Unexpected number of resources", TOTAL_RESOURCES / 2, filteredResources.length);
      for (TestResource resource : filteredResources)
      {
         // the "even" identity must be able to see only the "even" resources.
         assertTrue(resource.getResourceId() % 2 == 0);
      }

      // same test, now with an "odd" identity number.
      identity = this.identities[1];
      filteredResources = this.filterResources(identity);
      assertEquals("Unexpected number of resources", TOTAL_RESOURCES / 2, filteredResources.length);
      for (TestResource resource : filteredResources)
      {
         // the identity must be able to see only the "odd" resources.
         assertTrue(resource.getResourceId() % 2 == 1);
      }

      // now try to update some resources using an identity without the appropriate permission (identities[1]).
      for (TestResource resource : filteredResources)
      {
         this.updateResource(resource, identity);
         assertEquals("Resource name has changed", "Resource" + resource.getResourceId(), resource.getResourceName());
      }

      // repeat the test, this time using an identity with the appropriate permission (identities[5] has all perms).
      identity = this.identities[5];
      for (TestResource resource : filteredResources)
      {
         this.updateResource(resource, identity);
         assertEquals("Resource name hasn't changed as expected", "Changed Name", resource.getResourceName());
      }
   }

   /**
    * <p>
    * Utility method that uses ACLs to decide which resources the specified identity should be able to read.
    * </p>
    * 
    * @param identity   the {@code Identity} for which the resources are being filtered.
    * @return   an array of {@code TestResource} containig the resources the identity is allowed to read.
    */
   private TestResource[] filterResources(Identity identity)
   {
      List<TestResource> filteredResources = new ArrayList<TestResource>();
      // iterate through the resources and add those that can be accessed by the identity.
      for (TestResource resource : this.resources)
      {
         boolean isGranted = false;
         try
         {
            // check the identity has the READ permission on the resource.
            isGranted = this.provider.isAccessGranted(resource, identity, BasicACLPermission.READ);
         }
         catch (AuthorizationException ae)
         {
            fail("Unexpected exception: " + ae.getMessage());
         }
         if (isGranted)
         {
            filteredResources.add(resource);
         }
      }
      return filteredResources.toArray(new TestResource[filteredResources.size()]);
   }

   /**
    * <p>
    * Utility method that uses ACLs to decide if the specified identity is allowed to update the resource. If
    * it is, the resource's name is changed to {@code Changed Name}.
    * </p>
    * 
    * @param resource   the {@code TestResource} to be updated.
    * @param identity   the {@code Identity} that wants to update the resource.
    */
   private void updateResource(TestResource resource, Identity identity)
   {
      boolean isGranted = false;
      try
      {
         isGranted = this.provider.isAccessGranted(resource, identity, BasicACLPermission.UPDATE);
      }
      catch (AuthorizationException ae)
      {
         fail("Unexpected exception: " + ae.getMessage());
      }
      if (isGranted)
         resource.setResourceName("Changed Name");
   }

}
