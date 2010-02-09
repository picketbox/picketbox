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
package org.jboss.test.authorization.acl;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;

import org.jboss.security.acl.BasicACLPermission;
import org.jboss.security.acl.CompositeACLPermission;
import org.jboss.security.acl.EntitlementEntry;
import org.jboss.security.acl.config.ACLProviderEntry;
import org.jboss.security.authorization.AuthorizationContext;
import org.jboss.security.authorization.EntitlementHolder;
import org.jboss.security.authorization.PolicyRegistration;
import org.jboss.security.authorization.Resource;
import org.jboss.security.authorization.ResourceKeys;
import org.jboss.security.config.ACLInfo;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.SecurityConfiguration;
import org.jboss.security.identity.Identity;
import org.jboss.security.identity.plugins.IdentityFactory;
import org.jboss.security.plugins.JBossAuthorizationManager;
import org.jboss.security.plugins.JBossPolicyRegistration;

/**
 * ACL Unit Tests using JBossAuthorizationManager
 * 
 * @author Anil.Saldhana@redhat.com
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @since Jan 30, 2008
 * @version $Revision$
 */
public class JBossAuthorizationManagerACLUnitTestCase extends TestCase
{

   /*
    * (non-Javadoc)
    * 
    * @see junit.framework.TestCase#setUp()
    */
   @Override
   protected void setUp()
   {
      // register an ACL policy containing ACL definitions with the PolicyRegistration.
      PolicyRegistration registration = new JBossPolicyRegistration();
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream aclStream = tcl.getResourceAsStream("config/jboss-acl.xml");
      assertNotNull("ACL Config Stream is null", aclStream);
      registration.registerPolicy("ID", PolicyRegistration.ACL, aclStream);

      // create an application policy that contains an ACL configuration.
      ApplicationPolicy ap = new ApplicationPolicy("test-acl");
      ACLInfo aclInfo = new ACLInfo("test-acl");
      // set the TestACLProvider with the PolicyRegistration created above.
      Map<String, Object> options = new HashMap<String, Object>();
      options.put("policyRegistration", registration);
      ACLProviderEntry ame = new ACLProviderEntry(TestACLProvider.class.getName(), options);
      aclInfo.add(ame);
      ap.setAclInfo(aclInfo);
      // register the application policy.
      SecurityConfiguration.addApplicationPolicy(ap);
   }

   @Override
   protected void tearDown() throws Exception
   {
      // unregister the application policy.
      SecurityConfiguration.removeApplicationPolicy("test-acl");
   }

   /**
    * <p>
    * Tests the results of the {@code AuthorizationManager#getEntitlements} method when the ACLs have been specified in
    * an ACL configuration file and registered with the {@code PolicyRegistration}.
    * </p>
    * 
    * @throws Exception if an error occurs while running the test.
    */
   public void testGetEntitlements() throws Exception
   {
      Resource resource1 = new ACLTestResource(10);
      Resource resource2 = new ACLTestResource(20);
      // for testing purposes, lets say resource2 is a child of resource1.
      Collection<Resource> childResources = new ArrayList<Resource>();
      // resource 1 has resource 2 as child.
      childResources.add(resource2);
      resource1.getMap().put(ResourceKeys.CHILD_RESOURCES, childResources);
      resource2.getMap().put(ResourceKeys.PARENT_RESOURCE, resource1);

      // using the authorization manager, check the entitlements assigned to some of the identities.
      JBossAuthorizationManager jam = new JBossAuthorizationManager("test-acl");

      // start with the Administrator identity.
      EntitlementHolder<EntitlementEntry> holder = jam.getEntitlements(EntitlementEntry.class, resource1,
            IdentityFactory.createIdentity("Administrator"));
      assertNotNull("Unexpected null EntitlementHolder", holder);
      Set<EntitlementEntry> entitled = holder.getEntitled();
      assertNotNull("Unexpected null set of entitlement entries", entitled);
      assertEquals("Unexpected number of entitlement entries", 2, entitled.size());
      // Administrator should have all permissions on both resources.
      Map<Integer, EntitlementEntry> entriesMap = this.getEntriesByResourceID(entitled);
      CompositeACLPermission expectedPermission = new CompositeACLPermission(BasicACLPermission.values());
      assertTrue("Entry for ACLTestResource with id 10 missing", entriesMap.containsKey(10));
      assertEquals("Found unexpected permissions", expectedPermission, entriesMap.get(10).getPermission());
      assertTrue("Entry for ACLTestResource with id 20 missing", entriesMap.containsKey(20));
      assertEquals("Found unexpected permissions", expectedPermission, entriesMap.get(20).getPermission());

      // now check the permissions entitled to Regular_User.
      holder = jam.getEntitlements(EntitlementEntry.class, resource1, IdentityFactory.createIdentity("Regular_User"));
      assertNotNull("Unexpected null EntitlementHolder", holder);
      entitled = holder.getEntitled();
      assertNotNull("Unexpected null set of entitlement entries", entitled);
      // Regular_User should get an empty set when calling getEntitlements with resource1.
      assertEquals("Unexpected number of entitlement entries", 0, entitled.size());
      holder = jam.getEntitlements(EntitlementEntry.class, resource2, IdentityFactory.createIdentity("Regular_User"));
      assertNotNull("Unexpected null EntitlementHolder", holder);
      entitled = holder.getEntitled();
      assertNotNull("Unexpected null set of entitlement entries", entitled);
      assertEquals("Unexpected number of entitlement entries", 1, entitled.size());
      // Regular_User should have READ and UPDATE permissions on resource 2.
      entriesMap = this.getEntriesByResourceID(entitled);
      expectedPermission = new CompositeACLPermission(BasicACLPermission.READ, BasicACLPermission.UPDATE);
      assertTrue("Entry for ACLTestResource with id 20 missing", entriesMap.containsKey(20));
      assertEquals("Found unexpected permissions", expectedPermission, entriesMap.get(20).getPermission());
   }

   /**
    * <p>
    * Tests the results of the {@code AuthorizationManager#authorize} method when the ACLs have been specified in an ACL
    * configuration file and registered with the {@code PolicyRegistration}.
    * </p>
    * 
    * @throws Exception if an error occurs while running the test.
    */
   public void testAuthorize() throws Exception
   {
      Resource resource1 = new ACLTestResource(10);
      Resource resource2 = new ACLTestResource(20);

      // using the authorization manager, check if the identities have the expected permissions.
      JBossAuthorizationManager jam = new JBossAuthorizationManager("test-acl");

      // check that Administrator has all permissions on both resources.
      Identity identity = IdentityFactory.createIdentity("Administrator");
      assertEquals(AuthorizationContext.PERMIT, jam.authorize(resource1, identity, new CompositeACLPermission(
            BasicACLPermission.values())));
      assertEquals(AuthorizationContext.PERMIT, jam.authorize(resource2, identity, new CompositeACLPermission(
            BasicACLPermission.values())));

      // check that Guest has only READ permission on resource1.
      identity = IdentityFactory.createIdentity("Guest");
      assertEquals(AuthorizationContext.PERMIT, jam.authorize(resource1, identity, BasicACLPermission.READ));
      assertEquals(AuthorizationContext.DENY, jam.authorize(resource1, identity, BasicACLPermission.CREATE));
      assertEquals(AuthorizationContext.DENY, jam.authorize(resource1, identity, BasicACLPermission.UPDATE));
      assertEquals(AuthorizationContext.DENY, jam.authorize(resource1, identity, BasicACLPermission.DELETE));

      // check that Guest has READ and UPDATE permissions on resource2.
      assertEquals(AuthorizationContext.PERMIT, jam.authorize(resource2, identity, BasicACLPermission.READ));
      assertEquals(AuthorizationContext.PERMIT, jam.authorize(resource2, identity, BasicACLPermission.UPDATE));
      assertEquals(AuthorizationContext.PERMIT, jam.authorize(resource2, identity, new CompositeACLPermission(
            BasicACLPermission.READ, BasicACLPermission.UPDATE)));
      assertEquals(AuthorizationContext.DENY, jam.authorize(resource2, identity, BasicACLPermission.CREATE));
      assertEquals(AuthorizationContext.DENY, jam.authorize(resource2, identity, BasicACLPermission.DELETE));
      assertEquals(AuthorizationContext.DENY, jam.authorize(resource2, identity, new CompositeACLPermission(
            BasicACLPermission.values())));
      
      // check that Regular_User doesn't have any permissions on resource1.
      identity = IdentityFactory.createIdentity("Regular_User");
      for(BasicACLPermission permission : BasicACLPermission.values())
         assertEquals(AuthorizationContext.DENY, jam.authorize(resource1, identity, permission));
      
      // check that Regular_User has READ and UPDATE permissions on resource2.
      assertEquals(AuthorizationContext.PERMIT, jam.authorize(resource2, identity, BasicACLPermission.READ));
      assertEquals(AuthorizationContext.PERMIT, jam.authorize(resource2, identity, BasicACLPermission.UPDATE));
      assertEquals(AuthorizationContext.PERMIT, jam.authorize(resource2, identity, new CompositeACLPermission(
            BasicACLPermission.READ, BasicACLPermission.UPDATE)));
      assertEquals(AuthorizationContext.DENY, jam.authorize(resource2, identity, BasicACLPermission.CREATE));
      assertEquals(AuthorizationContext.DENY, jam.authorize(resource2, identity, BasicACLPermission.DELETE));
      assertEquals(AuthorizationContext.DENY, jam.authorize(resource2, identity, new CompositeACLPermission(
            BasicACLPermission.values())));
   }

   /**
    * <p>
    * Creates and returns a map that contains the specified set of {@code EntitlementEntry} objects keyed by their
    * resources ids.
    * </p>
    * 
    * @param entries the set of {@code EntitlementEntry} objects to be keyed.
    * @return the constructed {@code Map} instance.
    */
   private Map<Integer, EntitlementEntry> getEntriesByResourceID(Set<EntitlementEntry> entries)
   {
      Map<Integer, EntitlementEntry> entriesMap = new HashMap<Integer, EntitlementEntry>();
      for (EntitlementEntry entry : entries)
      {
         ACLTestResource testResource = (ACLTestResource) entry.getResource();
         entriesMap.put(testResource.getId(), entry);
      }
      return entriesMap;
   }
}
