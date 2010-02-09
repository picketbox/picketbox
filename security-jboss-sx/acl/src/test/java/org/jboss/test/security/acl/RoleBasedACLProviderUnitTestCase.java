/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2009, Red Hat Middleware LLC, and individual contributors
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
import java.util.List;

import junit.framework.TestCase;

import org.jboss.security.acl.ACLEntry;
import org.jboss.security.acl.ACLEntryImpl;
import org.jboss.security.acl.ACLPersistenceStrategy;
import org.jboss.security.acl.ACLProvider;
import org.jboss.security.acl.BasicACLPermission;
import org.jboss.security.acl.CompositeACLPermission;
import org.jboss.security.acl.JPAPersistenceStrategy;
import org.jboss.security.acl.RoleBasedACLProviderImpl;
import org.jboss.security.authorization.Resource;
import org.jboss.security.identity.Identity;
import org.jboss.security.identity.Role;
import org.jboss.security.identity.RoleFactory;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.identity.plugins.IdentityFactory;

/**
 * <p>
 * This {@code TestCase} tests the functionality implemented by the {@code RoleBasedACLProviderImpl} class.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class RoleBasedACLProviderUnitTestCase extends TestCase
{

   private Resource[] resources;

   private Identity identity;

   private final ACLPersistenceStrategy strategy = new JPAPersistenceStrategy();

   @Override
   protected void setUp() throws Exception
   {
      super.setUp();
      // build the test resources.
      this.resources = new Resource[2];
      for (int i = 0; i < resources.length; i++)
         resources[i] = new TestResource(i, "Test Resource " + i);

      // Identity 'john' has two roles (role1 and role2).
      Role role1 = RoleFactory.createRole("role1");
      Role role2 = RoleFactory.createRole("role2");
      RoleGroup roleGroup = RoleFactory.createRoleGroup("RoleGroup");
      roleGroup.addRole(role1);
      roleGroup.addRole(role2);
      this.identity = IdentityFactory.createIdentityWithRole("john", roleGroup);

      // create the ACLs for the resources.
      ACLEntry entry1 = new ACLEntryImpl(BasicACLPermission.READ, "role1");
      ACLEntry entry2 = new ACLEntryImpl(
            new CompositeACLPermission(BasicACLPermission.READ, BasicACLPermission.UPDATE), "role2");
      ACLEntry entry3 = new ACLEntryImpl(new CompositeACLPermission(BasicACLPermission.values()), "role3");
      List<ACLEntry> entries = new ArrayList<ACLEntry>();
      entries.add(entry1);
      entries.add(entry2);
      entries.add(entry3);
      this.strategy.createACL(this.resources[0], entries);

      // the second ACL uses the identity name.
      entry1 = new ACLEntryImpl(BasicACLPermission.READ, "ritchie");
      entry2 = new ACLEntryImpl(new CompositeACLPermission(BasicACLPermission.values()), "john");
      entries = new ArrayList<ACLEntry>();
      entries.add(entry1);
      entries.add(entry2);
      this.strategy.createACL(this.resources[1], entries);
   }

   /**
    * <p>
    * Tests the behavior of the {@code isAccessGranted} method, which uses the identity's roles to check whether
    * access to the resource should be granted or not.
    * </p>
    * 
    * @throws Exception if an error occurs while running the test.
    */
   public void testACLProvider() throws Exception
   {
      // create the RoleBasedACLProvider instance.
      ACLProvider provider = new RoleBasedACLProviderImpl();
      provider.setPersistenceStrategy(this.strategy);

      // as john has role 2, he should be able to update resource 0.
      assertTrue(provider.isAccessGranted(this.resources[0], this.identity, BasicACLPermission.UPDATE));
      // none of john's roles has DELETE permission, so he should not be able to delete resource 0.
      assertFalse(provider.isAccessGranted(this.resources[0], this.identity, BasicACLPermission.DELETE));

      // now create a new identity for john that has no roles. The role-based provider should now use the
      // identity name (default impl) when checking for permissions.
      Identity identity = IdentityFactory.createIdentity("john");
      assertTrue(provider.isAccessGranted(this.resources[1], identity, new CompositeACLPermission(BasicACLPermission
            .values())));
      // access should be denied to resource 0, as that one has an ACL based on the roles.
      assertFalse(provider.isAccessGranted(this.resources[0], identity, BasicACLPermission.READ));
   }

}
