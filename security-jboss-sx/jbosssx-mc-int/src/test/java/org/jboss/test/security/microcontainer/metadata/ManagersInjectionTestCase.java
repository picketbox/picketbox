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

import org.jboss.security.AuthenticationManager;
import org.jboss.security.AuthorizationManager;
import org.jboss.security.audit.AuditManager;
import org.jboss.security.identitytrust.IdentityTrustManager;
import org.jboss.security.mapping.MappingManager;
import org.jboss.test.kernel.junit.MicrocontainerTest;
import org.jboss.test.security.microcontainer.metadata.support.MockAuditManager;
import org.jboss.test.security.microcontainer.metadata.support.MockAuthenticationManager;
import org.jboss.test.security.microcontainer.metadata.support.MockAuthorizationManager;
import org.jboss.test.security.microcontainer.metadata.support.MockIdentityTrustManager;
import org.jboss.test.security.microcontainer.metadata.support.MockMappingManager;
import org.jboss.test.security.microcontainer.metadata.support.TestBean;
import org.jboss.xb.binding.sunday.unmarshalling.SingletonSchemaResolverFactory;

/**
 * <p>
 * This class tests the injection of the various security managers into a bean using an application policy
 * configuration. The following snippet shows an example of {@code AuthenticationManager} injection:
 * 
 * <pre>
 *  &lt;application-policy xmlns=&quot;urn:jboss:security-beans:1.0&quot; name=&quot;TestPolicy1&quot;&gt;
 *     &lt;authentication&gt;
 *        &lt;login-module code=&quot;org.jboss.security.auth.AuthModule1&quot; flag=&quot;required&quot;&gt;
 *           &lt;module-option name=&quot;authOption1&quot;&gt;value1&lt;/module-option&gt;
 *           &lt;module-option name=&quot;authOption2&quot;&gt;value2&lt;/module-option&gt;
 *        &lt;/login-module&gt;
 *     &lt;/authentication&gt;
 *  &lt;/application-policy&gt;
 * 
 *  &lt;bean name=&quot;TestBean&quot; class=&quot;org.jboss.test.security.microcontainer.metadata.support.TestBean&quot;&gt;
 *     &lt;property name=&quot;authenticationManager&quot;&gt;
 *        &lt;inject bean=&quot;TestPolicy1&quot; property=&quot;authenticationManager&quot;/&gt;
 *     &lt;/property&gt;
 *  &lt;/bean&gt;
 * </pre>
 * 
 * As we can see from the example, the {@code ApplicationPolicyBean} that is generated when the policy is parsed can be
 * used by other beans to obtain the security managers that are responsible for enforcing the specified policy. In the
 * example above, a bean uses the policy named {@code TestPolicy1} to obtain the {@code AuthenticationManager} through
 * injection.
 * </p>
 * <p>
 * The following {@code ApplicationPolicyBean} properties are available for other beans to retrieve the security
 * managers:
 * <ul>
 * <li>authenticationManager - retrieves the {@code AuthenticationManager} that uses the {@code <authentication>}
 * configuration to authenticate users.</li>
 * <li>authorizationManager - retrieves the {@code AuthorizationManager} that uses the {@code <authorization>}
 * configuration to authorize access to resources.</li>
 * <li>mappingManager - retrieves the {@code MappingManager} that uses the {@code <rolemapping>} and {@code <mapping>}
 * configurations to map roles and identities.</li>
 * <li>auditManager - retrieves the {@code AuditManager} that uses the {@code <audit>} configuration to perform
 * auditing.</li>
 * <li>identityTrustManager - retrieves the {@code IdentityTrustManager} that uses the {@code <identity-trust>}
 * configuration.</li>
 * </ul>
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class ManagersInjectionTestCase extends MicrocontainerTest
{

   /**
    * <p>
    * Creates an instance of {@code ManagersInjectionTestCase} with the specified name.
    * </p>
    * 
    * @param name a {@code String} representing the name of this test case.
    */
   public ManagersInjectionTestCase(String name)
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
    * Tests the injection of all security managers into a {@code TestBean}. All managers are represented by mock
    * objects.
    * </p>
    * 
    * @throws Exception if an error occurs while running the tests.
    */
   public void testManagersInjection() throws Exception
   {
      // get the test bean and validate all mock managers have been injected.
      TestBean testBean = (TestBean) super.getBean("TestBean");
      assertNotNull("TestBean could not be found", testBean);

      // check the authentication manager injection.
      AuthenticationManager authenticationManager = testBean.getAuthenticationManager();
      assertNotNull("Invalid null AuthenticationManager found", authenticationManager);
      assertEquals("Invalid AuthenticationManager implementation found", MockAuthenticationManager.class,
            authenticationManager.getClass());
      assertEquals("TestPolicy1", authenticationManager.getSecurityDomain());

      // check the authorization manager injection.
      AuthorizationManager authorizationManager = testBean.getAuthorizationManager();
      assertNotNull("Invalid null AuthorizationManager found", authorizationManager);
      assertEquals("Invalid AuthorizationManager implementation found", MockAuthorizationManager.class,
            authorizationManager.getClass());
      assertEquals("TestPolicy1", authorizationManager.getSecurityDomain());

      // check the mapping manager injection.
      MappingManager mappingManager = testBean.getMappingManager();
      assertNotNull("Invalid null MappingManager found", mappingManager);
      assertEquals("Invalid MappingManager implementation found", MockMappingManager.class, mappingManager.getClass());
      assertEquals("TestPolicy1", mappingManager.getSecurityDomain());

      // check the audit manager injection.
      AuditManager auditManager = testBean.getAuditManager();
      assertNotNull("Invalid null AuditManager found", auditManager);
      assertEquals("Invalid AuditManager implementation found", MockAuditManager.class, auditManager.getClass());
      assertEquals("TestPolicy1", auditManager.getSecurityDomain());

      // check the identity-trust injection.
      IdentityTrustManager trustManager = testBean.getIdentityTrustManager();
      assertNotNull("Invalid null IdentityTrustManager found", trustManager);
      assertEquals("Invalid IdentityTrustManager implementation found", MockIdentityTrustManager.class, trustManager
            .getClass());
      assertEquals("TestPolicy1", trustManager.getSecurityDomain());

   }
}
