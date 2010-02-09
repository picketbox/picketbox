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
package org.jboss.test.security.microcontainer.metadata;

import org.jboss.test.kernel.junit.MicrocontainerTest;
import org.jboss.xb.binding.JBossXBException;
import org.jboss.xb.binding.sunday.unmarshalling.SingletonSchemaResolverFactory;

/**
 * <p>
 * This class implements a {@code MicrocontainerTest} that aims to validate the behavior of the
 * {@code ApplicationPolicyMetaDataFactory} when invalid application policies are deployed.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class InvalidApplicationPolicyTestCase extends MicrocontainerTest
{

   /**
    * <p>
    * Creates an instance of {@code InvalidApplicationPolicyTestCase} with the specified name.
    * </p>
    * 
    * @param name a {@code String} representing the name of this test case.
    */
   public InvalidApplicationPolicyTestCase(String name)
   {
      super(name);
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.test.kernel.junit.MicrocontainerTest#setUp()
    */
   @Override
   protected void setUp() throws Exception
   {
      // register the schema to the schema resolver before deploying the xml configuration file.
      SingletonSchemaResolverFactory.getInstance().addJaxbSchema("urn:jboss:security-beans:1.0",
            "org.jboss.security.microcontainer.beans.metadata.SecurityPolicyMetaData");
      super.setUp();
   }

   /**
    * <p>
    * Tests the deployment of invalid application policies, verifying that the expected exceptions are thrown.
    * </p>
    * 
    * @throws Exception if an error occurs while running the test.
    */
   public void testInvalidApplicationPolicies() throws Exception
   {
      boolean exceptionCaught = false;
      try
      {
         // deploy an invalid policy that does not declare any authentication configuration.
         super.deploy(this.getClass().getResource("InvalidApplicationPolicy1.xml"));
      }
      catch (Exception e)
      {
         assertTrue(e instanceof RuntimeException);
         assertEquals("An application policy must have an authentication or authentication-jaspi configuration", e
               .getMessage());
         exceptionCaught = true;
      }
      assertTrue("Expected exception has not been thrown", exceptionCaught);

      exceptionCaught = false;
      try
      {
         // deploy an invalid policy that declares both types of authentication configuration.
         super.deploy(this.getClass().getResource("InvalidApplicationPolicy2.xml"));
      }
      catch (Exception e)
      {
         // expected exception chain: JBossXBException -> RuntimeException -> IllegalArgumentException.
         assertTrue(e instanceof JBossXBException);
         assertTrue(e.getCause() instanceof RuntimeException);
         Throwable rootCause = e.getCause().getCause();
         assertTrue(rootCause instanceof IllegalArgumentException);
         assertEquals("An <authentication> configuration has already been defined for the policy", rootCause
               .getMessage());
         exceptionCaught = true;
      }
      assertTrue("Expected exception has not been thrown", exceptionCaught);
   }
}
