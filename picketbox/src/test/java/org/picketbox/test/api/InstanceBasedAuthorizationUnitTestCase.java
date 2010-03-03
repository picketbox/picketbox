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
package org.picketbox.test.api;

import java.net.URI;
import java.security.Principal;
import java.security.acl.Group;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;

import junit.framework.TestCase;

import org.jboss.security.AuthenticationManager;
import org.jboss.security.AuthorizationManager;
import org.jboss.security.acl.ACLEntry;
import org.jboss.security.acl.ACLEntryImpl;
import org.jboss.security.acl.ACLPersistenceStrategy;
import org.jboss.security.acl.BasicACLPermission;
import org.jboss.security.acl.BitMaskPermission;
import org.jboss.security.acl.CompositeACLPermission;
import org.jboss.security.acl.EntitlementEntry;
import org.jboss.security.authorization.AuthorizationContext;
import org.jboss.security.authorization.Resource;
import org.jboss.security.authorization.ResourceKeys;
import org.jboss.security.authorization.ResourceType;
import org.jboss.security.identity.plugins.IdentityFactory;
import org.picketbox.config.PicketBoxConfiguration;
import org.picketbox.factories.SecurityFactory;
import org.picketbox.test.acl.MemoryOnlyACLStrategy;

/**
 * <p>
 * This {@code TestCase} tests the behavior of the instance-based authorization mechanism (ACLs). All tests use a
 * memory-based {@code ACLPersistenceStrategy} implementation. Real world scenarios will most likely require an
 * implementation that stores the ACLs on the file systems or databases.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class InstanceBasedAuthorizationUnitTestCase extends TestCase
{
   private final String securityDomainName = "test";

   private final String configFile = "config/acl-authorization.conf";

   private final Resource importantResource1 = new TestResource("file://documents/project/important-file1");
   
   private final Resource importantResource2 = new TestResource("file://documents/project/important-file2");
   
   private boolean initialized;

   @Override
   protected void setUp() throws Exception
   {
      super.setUp();
      // setup the static test ACLs only once.
      if (!this.initialized)
      {
         ACLPersistenceStrategy strategy = new MemoryOnlyACLStrategy();

         // create an ACL for important-file1.
         // project managers may read, update and delete the file.
         ACLEntry entry1 = new ACLEntryImpl(new CompositeACLPermission(BasicACLPermission.values()), "manager");
         // project developers can only view the contents of the file.
         ACLEntry entry2 = new ACLEntryImpl(BasicACLPermission.READ, "developer");
         Collection<ACLEntry> entries = new ArrayList<ACLEntry>();
         entries.add(entry1);
         entries.add(entry2);
         // create and register the ACLs in the persistence strategy.
         strategy.createACL(this.importantResource1, entries);
         
         // we won't create an ACL for important-file2 - we will make it a child resource of important-file1.
         Collection<Resource> children = new ArrayList<Resource>();
         children.add(importantResource2);
         this.importantResource2.getMap().put(ResourceKeys.PARENT_RESOURCE, this.importantResource1);
         this.importantResource1.getMap().put(ResourceKeys.CHILD_RESOURCES, children);
         this.initialized = true;
      }
   }

   /**
    * <p>
    * This test verifies if the instance-based authorization mechanism correctly grants/denies access to a resource
    * according to the permissions that have been specified in the resource's ACL (importantResource1).  
    * </p>
    * 
    * @throws Exception if an error occurs while running the test.
    */
   public void testAuthorizationBasedOnResourceACL() throws Exception
   {
      SecurityFactory.prepare();
      try
      {
         PicketBoxConfiguration idtrustConfig = new PicketBoxConfiguration();
         idtrustConfig.load(configFile);

         AuthenticationManager authManager = SecurityFactory.getAuthenticationManager(securityDomainName);
         assertNotNull(authManager);

         // bob, the project manager authenticates to the system.
         Subject subject = new Subject();
         boolean result = authManager.isValid(this.getPrincipal("bob"), "bobpass", subject);
         assertTrue("Unexpected authentication error", result);

         // now bob wants to update the important project file. We must check if he has permission to do so.
         AuthorizationManager authzManager = SecurityFactory.getAuthorizationManager(securityDomainName);
         assertNotNull(authzManager);

         // first we get bob's roles from the subject (the ACL entries have roles as keys).
         Group roles = subject.getPrincipals(Group.class).iterator().next();
         assertEquals("Unexpected group name", "Roles", roles.getName());
         Enumeration<?> rolesEnum = roles.members();

         // now we must check if any of bob's roles has the permission to update the file.
         int decision = AuthorizationContext.DENY;
         while (rolesEnum.hasMoreElements() && decision == AuthorizationContext.DENY)
         {
            Principal role = (Principal) rolesEnum.nextElement();
            decision = authzManager.authorize(this.importantResource1, IdentityFactory.createIdentity(role.getName()),
                  BasicACLPermission.UPDATE);
         }
         // as we know, bob is a manager, so the final decision should allow him to update the project file.
         assertEquals("Unexpected authorization decision", AuthorizationContext.PERMIT, decision);
         
         // now alice, the project developer, authenticates to the system.
         subject = new Subject();
         result = authManager.isValid(this.getPrincipal("alice"), "alicepass", subject);
         assertTrue("Unexpected authentication error", result);
         
         // alice tries to delete the important project file. We must check if she has sufficient permissions.
         // first we get alice's roles from the subject.
         roles = subject.getPrincipals(Group.class).iterator().next();
         assertEquals("Unexpected group name", "Roles", roles.getName());
         rolesEnum = roles.members();

         // then we check if any of alice's roles has the permission to delete the file.
         decision = AuthorizationContext.DENY;
         while (rolesEnum.hasMoreElements() && decision == AuthorizationContext.DENY)
         {
            Principal role = (Principal) rolesEnum.nextElement();
            decision = authzManager.authorize(this.importantResource1, IdentityFactory.createIdentity(role.getName()),
                  BasicACLPermission.DELETE);
         }
         // as we know, alice is only a developer, so the final decision should prevent her from deleting the file.
         assertEquals("Unexpected authorization decision", AuthorizationContext.DENY, decision);
      }
      finally
      {
         SecurityFactory.release();
      }
   }

   /**
    * <p>
    * This test verifies if access to {@code important-file2} is granted/denied based on the permissions specified
    * on its parent resource ACL. In other words, we haven't specified an ACL for {@code important-file2} but
    * we made this resource a child of {@code important-file1}, so we expect the ACL of the parent resource
    * ({@code important-file1}) to be used to perform the authorization check.
    * </p>
    * 
    * @throws Exception if an error occurs while running the test.
    */
   public void testAuthorizationBasedOnParentResourceACL() throws Exception
   {
      SecurityFactory.prepare();
      try
      {
         PicketBoxConfiguration idtrustConfig = new PicketBoxConfiguration();
         idtrustConfig.load(configFile);

         AuthenticationManager authManager = SecurityFactory.getAuthenticationManager(securityDomainName);
         assertNotNull(authManager);

         // bob, the project manager authenticates to the system.
         Subject subject = new Subject();
         boolean result = authManager.isValid(this.getPrincipal("bob"), "bobpass", subject);
         assertTrue("Unexpected authentication error", result);

         // now bob wants to update the important-file2. We must check if he has permission to do so.
         AuthorizationManager authzManager = SecurityFactory.getAuthorizationManager(securityDomainName);
         assertNotNull(authzManager);

         // first we get bob's roles from the subject (the ACL entries have roles as keys).
         Group roles = subject.getPrincipals(Group.class).iterator().next();
         assertEquals("Unexpected group name", "Roles", roles.getName());
         Enumeration<?> rolesEnum = roles.members();

         // now we must check if any of bob's roles has the permission to update the file.
         int decision = AuthorizationContext.DENY;
         while (rolesEnum.hasMoreElements() && decision == AuthorizationContext.DENY)
         {
            Principal role = (Principal) rolesEnum.nextElement();
            decision = authzManager.authorize(this.importantResource2, IdentityFactory.createIdentity(role.getName()),
                  BasicACLPermission.UPDATE);
         }
         // as we know, bob is a manager, so the final decision should allow him to update the project file.
         // this has been specified in the parent resource (important-file1) ACL.
         assertEquals("Unexpected authorization decision", AuthorizationContext.PERMIT, decision);
         
         // now alice, the project developer, authenticates to the system.
         subject = new Subject();
         result = authManager.isValid(this.getPrincipal("alice"), "alicepass", subject);
         assertTrue("Unexpected authentication error", result);
         
         // alice tries to delete the important-file2. We must check if she has sufficient permissions.
         // first we get alice's roles from the subject.
         roles = subject.getPrincipals(Group.class).iterator().next();
         assertEquals("Unexpected group name", "Roles", roles.getName());
         rolesEnum = roles.members();

         // then we check if any of alice's roles has the permission to delete the file.
         decision = AuthorizationContext.DENY;
         while (rolesEnum.hasMoreElements() && decision == AuthorizationContext.DENY)
         {
            Principal role = (Principal) rolesEnum.nextElement();
            decision = authzManager.authorize(this.importantResource2, IdentityFactory.createIdentity(role.getName()),
                  BasicACLPermission.DELETE);
         }
         // as we know, alice is only a developer, so the final decision should prevent her from deleting the file.
         assertEquals("Unexpected authorization decision", AuthorizationContext.DENY, decision);
      }
      finally
      {
         SecurityFactory.release();
      }
   }
   
   /**
    * <p>
    * This test verifies if the {@code ACLProvider#getEntitlements()} method returns the expected set of entries.
    * </p>
    * 
    * @throws Exception if an error occurs while running the test.
    */
   public void testGetEntitlements() throws Exception
   {
      SecurityFactory.prepare();
      try
      {
         PicketBoxConfiguration idtrustConfig = new PicketBoxConfiguration();
         idtrustConfig.load(configFile);

         // get all the permissions assigned to managers on important-file1 and all its child resources. 
         AuthorizationManager authzManager = SecurityFactory.getAuthorizationManager(securityDomainName);
         assertNotNull(authzManager);
         
         Set<EntitlementEntry> entries = authzManager.getEntitlements(EntitlementEntry.class, 
               this.importantResource1, IdentityFactory.createIdentity("manager")).getEntitled();
         assertNotNull("Unexpected null entitlement entry set", entries);
         assertEquals("Unexpected number of entitlement entries", 2, entries.size());
         
         // check if each entry corresponds to each one of the important files and that managers have all permissions.
         boolean validatedImportantFile1Entry = false;
         boolean validatedImportantFile2Entry = false;
         for(EntitlementEntry entry : entries)
         {
            if (entry.getResource().equals(this.importantResource1))
               validatedImportantFile1Entry = true;
            else if (entry.getResource().equals(this.importantResource2))
               validatedImportantFile2Entry = true;
            else
               fail("Unexpected resource found in entitlement entry set");
            // validate the permissions assigned to the manager role.
            BitMaskPermission permission = (BitMaskPermission) entry.getPermission();
            BitMaskPermission expectedPermission = new CompositeACLPermission(BasicACLPermission.values());
            assertEquals("Unexpected permissions found in entry", expectedPermission.getMaskValue(), 
                  permission.getMaskValue());
         }
         assertTrue("Important file 1 entry is missing", validatedImportantFile1Entry);
         assertTrue("Important file 2 entry is missing", validatedImportantFile2Entry);
         
         // now get the entitlements entries for the developer role on important-file2.
         entries = authzManager.getEntitlements(EntitlementEntry.class, 
               this.importantResource2, IdentityFactory.createIdentity("developer")).getEntitled();
         assertNotNull("Unexpected null entitlement entry set", entries);
         assertEquals("Unexpected number of entitlement entries", 1, entries.size());
         
         // the single entry must contain the important-file2 resource and the READ permission.
         EntitlementEntry entry = entries.iterator().next();
         assertEquals("Unexpected resource found in entry", this.importantResource2, entry.getResource());
         BitMaskPermission permission = (BitMaskPermission) entry.getPermission();
         assertEquals("Unexpected permissions found in entry", BasicACLPermission.READ.getMaskValue(), 
               permission.getMaskValue());
      }
      finally
      {
         SecurityFactory.release();
      }
      
   }
   
   private Principal getPrincipal(final String name)
   {
      return new Principal()
      {
         public String getName()
         {
            return name;
         }
      };
   }

   class TestResource implements Resource
   {
      private URI resourceURI;

      private Map<String, Object> contextMap;
      
      public TestResource(String resourceURI)
      {
         this.resourceURI = URI.create(resourceURI);
         this.contextMap = new HashMap<String, Object>();
      }

      public ResourceType getLayer()
      {
         return ResourceType.ACL;
      }

      public Map<String, Object> getMap()
      {
         return this.contextMap;
      }

      /**
       * <p>
       * Let's consider two {@code TestResources} to be equal if they have the same resource URI.
       * </p>
       */
      @Override
      public boolean equals(Object obj)
      {
         if (obj instanceof TestResource)
         {
            TestResource other = (TestResource) obj;
            return other.resourceURI.equals(this.resourceURI);
         }
         return false;
      }

      @Override
      public int hashCode()
      {
         return this.resourceURI.hashCode();
      }
      
      @Override
      public String toString()
      {
         return this.resourceURI.toString();
      }
   }
}
