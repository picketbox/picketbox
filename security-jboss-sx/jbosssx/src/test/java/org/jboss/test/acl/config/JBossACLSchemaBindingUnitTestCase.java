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
package org.jboss.test.acl.config;

import java.util.Collection;

import org.jboss.security.acl.ACL;
import org.jboss.security.acl.ACLEntry;
import org.jboss.security.acl.ACLImpl;
import org.jboss.security.acl.BasicACLPermission;
import org.jboss.security.acl.CompositeACLPermission;
import org.jboss.security.acl.config.ACLConfiguration;
import org.jboss.security.identity.plugins.IdentityFactory;
import org.jboss.test.AbstractJBossSXTest;
import org.jboss.xb.binding.Unmarshaller;
import org.jboss.xb.binding.UnmarshallerFactory;
import org.jboss.xb.binding.sunday.unmarshalling.SchemaBinding;
import org.jboss.xb.binding.sunday.unmarshalling.XsdBinder;

/**
 * <p>
 * Tests the configuration of ACLs using an XML file that adheres to the {@code jboss-acl-configuration} schema.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class JBossACLSchemaBindingUnitTestCase extends AbstractJBossSXTest
{

   private final String schemaFile = "schema/jboss-acl-config_1_0.xsd";

   private final String xmlFile = "config/jboss-acl.xml";

   private ACLConfiguration configuration;

   /**
    * <p>
    * Creates an instance of {@code JBossACLSchemaBindingUnitTestCase} with the specified name.
    * </p>
    * 
    * @param name a {@code String} containing the name of this test case.
    */
   public JBossACLSchemaBindingUnitTestCase(String name)
   {
      super(name);
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.test.AbstractJBossSXTest#setUp()
    */
   @Override
   protected void setUp() throws Exception
   {
      super.setUp();

      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      SchemaBinding schema = XsdBinder.bind(tcl.getResourceAsStream(schemaFile), null);
      Unmarshaller unmarshaller = UnmarshallerFactory.newInstance().newUnmarshaller();
      this.configuration = (ACLConfiguration) unmarshaller.unmarshal(tcl.getResourceAsStream(xmlFile), schema);
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.test.AbstractTestCaseWithSetup#tearDown()
    */
   @Override
   protected void tearDown() throws Exception
   {
      this.configuration = null;
   }

   /**
    * <p>
    * Tests the correct creation of {@code ACL} objects according to the ACLs specified in the {@code jboss-acl.xml}
    * test file.
    * </p>
    * 
    * @throws Exception if an error occurs while running the test.
    */
   public void testACLConfiguration() throws Exception
   {
      assertNotNull("Unexpected null ACLConfiguration", this.configuration);
      Collection<ACL> configuredACLs = this.configuration.getConfiguredACLs();
      assertEquals("Invalid number of ACLs found", 2, configuredACLs.size());

      boolean validatedJavaCompACL = false;
      boolean validatedJavaCompEnvACL = false;

      // validate the two ACLs returned.
      for (ACL acl : configuredACLs)
      {
         ACLImpl aclImpl = (ACLImpl) acl;
         if (aclImpl.getResourceAsString().equals("org.jboss.test.authorization.acl.ACLTestResource:10"))
         {
            assertEquals("Invalid number of entries", 2, aclImpl.getEntries().size());
            // one entry should assign the CREATE,READ,UPDATE,DELETE permissions to Administrator.
            ACLEntry entry = aclImpl.getEntry(IdentityFactory.createIdentity("Administrator"));
            assertNotNull("Unexpected null value for Administrator entry", entry);
            CompositeACLPermission expectedPermission = new CompositeACLPermission(BasicACLPermission.values());
            assertEquals("Unexpected permissions assigned for Administrator", expectedPermission, entry.getPermission());
            // the other entry should assign the READ permission to Guest.
            entry = aclImpl.getEntry(IdentityFactory.createIdentity("Guest"));
            assertNotNull("Unexpected null value for Guest entry", entry);
            expectedPermission = new CompositeACLPermission(BasicACLPermission.READ);
            assertEquals("Unexpected permissions assigned for Guest", expectedPermission, entry.getPermission());
            validatedJavaCompACL = true;
         }
         else if (aclImpl.getResourceAsString().equals("org.jboss.test.authorization.acl.ACLTestResource:20"))
         {
            assertEquals("Invalid number of entries", 3, aclImpl.getEntries().size());
            // one entry should assign the CREATE,READ,UPDATE,DELETE permissions to Administrator.
            ACLEntry entry = aclImpl.getEntry(IdentityFactory.createIdentity("Administrator"));
            assertNotNull("Unexpected null value for Administrator entry", entry);
            CompositeACLPermission expectedPermission = new CompositeACLPermission(BasicACLPermission.values());
            assertEquals("Unexpected permissions assigned for Administrator", expectedPermission, entry.getPermission());
            // one other entry should assign the READ,UPDATE permissions to Guest.
            entry = aclImpl.getEntry(IdentityFactory.createIdentity("Guest"));
            assertNotNull("Unexpected null value for Guest entry", entry);
            expectedPermission = new CompositeACLPermission(BasicACLPermission.READ, BasicACLPermission.UPDATE);
            assertEquals("Unexpected permissions assigned for Guest", expectedPermission, entry.getPermission());
            // the final entry should assign the READ,UPDATE permissions to Regular_User.
            entry = aclImpl.getEntry(IdentityFactory.createIdentity("Regular_User"));
            assertNotNull("Unexpected null value for Regular_User entry", entry);
            expectedPermission = new CompositeACLPermission(BasicACLPermission.READ, BasicACLPermission.UPDATE);
            assertEquals("Unexpected permissions assigned for Regular_User", expectedPermission, entry.getPermission());
            validatedJavaCompEnvACL = true;
         }
         else
            fail("Invalid ACL found: " + aclImpl.getResourceAsString());
      }
      assertTrue("org.jboss.jnp.NamingService:java/comp ACL has not been validated", validatedJavaCompACL);
      assertTrue("org.jboss.jnp.NamingService:java/comp/env ACL has not been validated", validatedJavaCompEnvACL);
   }
}
