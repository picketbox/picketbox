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

import org.jboss.security.auth.login.AuthenticationInfo;
import org.jboss.security.auth.login.JASPIAuthenticationInfo;
import org.jboss.security.auth.login.XMLLoginConfigImpl;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.microcontainer.beans.ApplicationPolicyBean;
import org.jboss.test.kernel.junit.MicrocontainerTest;
import org.jboss.xb.binding.sunday.unmarshalling.SingletonSchemaResolverFactory;

/**
 * <p>
 * This class tests the application policy extension mechanism. The deployed configuration file specifies an application
 * policy named "TestPolicy2" that extends another application policy, named "TestPolicy1". The modules declared by the
 * "TestPolicy2" policy are added to the modules "inherited" from the extended "TestPolicy1" policy:
 * 
 * <pre>
 *  &lt;application-policy xmlns=&quot;urn:jboss:security-beans:1.0&quot; name=&quot;TestPolicy1&quot;&gt;
 *     &lt;authentication&gt;
 *        &lt;login-module code=&quot;org.jboss.security.auth.AuthModule1&quot; flag=&quot;required&quot;&gt;
 *           &lt;module-option name=&quot;authOption1&quot;&gt;value1&lt;/module-option&gt;
 *           &lt;module-option name=&quot;authOption2&quot;&gt;value2&lt;/module-option&gt;
 *        &lt;/login-module&gt;
 *     &lt;/authentication&gt;
 *     &lt;authorization&gt;
 *        &lt;policy-module code=&quot;org.jboss.security.authz.AuthorizationModule1&quot; flag=&quot;required&quot;&gt;
 *           &lt;module-option name=&quot;authzOption1&quot;&gt;value1&lt;/module-option&gt;
 *           &lt;module-option name=&quot;authzOption2&quot;&gt;value2&lt;/module-option&gt;
 *        &lt;/policy-module&gt;
 *     &lt;/authorization&gt;
 *     &lt;acl&gt;
 *        &lt;acl-module code=&quot;org.jboss.security.authz.ACLModule1&quot; flag=&quot;required&quot;&gt;
 *           &lt;module-option name=&quot;aclOption1&quot;&gt;value1&lt;/module-option&gt;
 *           &lt;module-option name=&quot;aclOption2&quot;&gt;value2&lt;/module-option&gt;
 *        &lt;/acl-module&gt;
 *     &lt;/acl&gt;
 *     &lt;rolemapping&gt;
 *        &lt;mapping-module code=&quot;org.jboss.security.mapping.RoleMappingModule1&quot;&gt;
 *           &lt;module-option name=&quot;mappingOption1&quot;&gt;value1&lt;/module-option&gt;
 *           &lt;module-option name=&quot;mappingOption2&quot;&gt;value2&lt;/module-option&gt;
 *        &lt;/mapping-module&gt;
 *        &lt;mapping-module code=&quot;org.jboss.security.mapping.RoleMappingModule2&quot;&gt;
 *           &lt;module-option name=&quot;mappingOption3&quot;&gt;value3&lt;/module-option&gt;
 *           &lt;module-option name=&quot;mappingOption4&quot;&gt;value4&lt;/module-option&gt;
 *        &lt;/mapping-module&gt;
 *     &lt;/rolemapping&gt;
 *     &lt;audit&gt;
 *        &lt;provider-module code=&quot;org.jboss.security.audit.AuditModule1&quot;&gt;
 *           &lt;module-option name=&quot;auditOption1&quot;&gt;value1&lt;/module-option&gt;
 *        &lt;/provider-module&gt;
 *     &lt;/audit&gt;
 *  &lt;/application-policy&gt;
 * 
 *  &lt;application-policy xmlns=&quot;urn:jboss:security-beans:1.0&quot; name=&quot;TestPolicy2&quot; extends=&quot;TestPolicy1&quot;&gt;
 *     &lt;authentication&gt;
 *        &lt;login-module code=&quot;org.jboss.security.auth.AuthModule2&quot; flag=&quot;optional&quot;&gt;
 *           &lt;module-option name=&quot;authOption3&quot;&gt;value3&lt;/module-option&gt;
 *           &lt;module-option name=&quot;authOption4&quot;&gt;value4&lt;/module-option&gt;
 *        &lt;/login-module&gt;
 *     &lt;/authentication&gt;
 *     &lt;authorization&gt;
 *        &lt;policy-module code=&quot;org.jboss.security.authz.AuthorizationModule2&quot; flag=&quot;required&quot;&gt;
 *           &lt;module-option name=&quot;authzOption3&quot;&gt;value3&lt;/module-option&gt;
 *           &lt;module-option name=&quot;authzOption4&quot;&gt;value4&lt;/module-option&gt;
 *        &lt;/policy-module&gt;
 *     &lt;/authorization&gt;
 *     &lt;acl&gt;
 *        &lt;acl-module code=&quot;org.jboss.security.authz.ACLModule2&quot; flag=&quot;required&quot;&gt;
 *           &lt;module-option name=&quot;aclOption3&quot;&gt;value3&lt;/module-option&gt;
 *           &lt;module-option name=&quot;aclOption4&quot;&gt;value4&lt;/module-option&gt;
 *        &lt;/acl-module&gt;
 *     &lt;/acl&gt;
 *     &lt;audit&gt;
 *        &lt;provider-module code=&quot;org.jboss.security.audit.AuditModule2&quot;&gt;
 *           &lt;module-option name=&quot;auditOption2&quot;&gt;value2&lt;/module-option&gt;
 *        &lt;/provider-module&gt;
 *     &lt;/audit&gt;
 *     &lt;identity-trust&gt;
 *        &lt;trust-module code=&quot;org.jboss.security.trust.IdentityTrustModule1&quot; flag=&quot;required&quot;&gt;
 *           &lt;module-option name=&quot;trustOption1&quot;&gt;value1&lt;/module-option&gt;
 *           &lt;module-option name=&quot;trustOption2&quot;&gt;value2&lt;/module-option&gt;
 *        &lt;/trust-module&gt;
 *     &lt;/identity-trust&gt;
 *  &lt;/application-policy&gt;
 * </pre>
 * 
 * </p>
 * <p>
 * The configuration file also specifies two policies that use the jaspi configuration and one of the policies extends
 * the other:
 * 
 * <pre>
 *  &lt;!-- an application policy using a jaspi configuration --&gt;
 *  &lt;application-policy xmlns=&quot;urn:jboss:security-beans:1.0&quot; name=&quot;TestPolicy3&quot;&gt;
 *     &lt;authentication-jaspi&gt;
 *        &lt;login-module-stack name=&quot;ModuleStack1&quot;&gt;
 *           &lt;login-module code=&quot;org.jboss.security.auth.AuthModule3&quot; flag=&quot;required&quot;&gt;
 *              &lt;module-option name=&quot;authOption5&quot;&gt;value5&lt;/module-option&gt;
 *           &lt;/login-module&gt;
 *           &lt;login-module code=&quot;org.jboss.security.auth.AuthModule4&quot; flag=&quot;optional&quot;/&gt;
 *        &lt;/login-module-stack&gt;
 *        &lt;auth-module code=&quot;org.jboss.security.auth.AuthModule1&quot; login-module-stack-ref=&quot;ModuleStack1&quot;/&gt;
 *     &lt;/authentication-jaspi&gt;
 *  &lt;/application-policy&gt;
 * 
 *  &lt;!-- an application policy that extends the TestPolicy3 to specify new jaspi configurations --&gt;
 *  &lt;application-policy xmlns=&quot;urn:jboss:security-beans:1.0&quot; name=&quot;TestPolicy4&quot; extends=&quot;TestPolicy3&quot;&gt;
 *     &lt;authentication-jaspi&gt;
 *        &lt;login-module-stack name=&quot;ModuleStack2&quot;&gt;
 *           &lt;login-module code=&quot;org.jboss.security.auth.AuthModule5&quot; flag=&quot;required&quot;&gt;
 *              &lt;module-option name=&quot;authOption6&quot;&gt;value6&lt;/module-option&gt;
 *              &lt;module-option name=&quot;authOption7&quot;&gt;value7&lt;/module-option&gt;
 *           &lt;/login-module&gt;
 *        &lt;/login-module-stack&gt;
 *        &lt;auth-module code=&quot;org.jboss.security.auth.AuthModule2&quot; login-module-stack-ref=&quot;ModuleStack2&quot;&gt;
 *           &lt;module-option name=&quot;authOption1&quot;&gt;value1&lt;/module-option&gt;
 *           &lt;module-option name=&quot;authOption2&quot;&gt;value2&lt;/module-option&gt;
 *        &lt;/auth-module&gt;
 *     &lt;/authentication-jaspi&gt;
 *  &lt;/application-policy&gt;
 * 
 * </pre>
 * 
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class ApplicationPolicyExtendsTestCase extends MicrocontainerTest
{

   /**
    * <p>
    * Creates an instance of {@code ApplicationPolicyExtendsTestCase} with the specified name.
    * </p>
    * 
    * @param name a {@code String} representing the name of this test case.
    */
   public ApplicationPolicyExtendsTestCase(String name)
   {
      super(name);
   }

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
    * Tests the creation of an {@code ApplicationPolicy} that extends another policy.
    * </p>
    * 
    * @throws Exception if an error occurs while running the test.
    */
   public void testCompletePolicyCreation() throws Exception
   {
      // check the bean constructed by the metadata factory has the parent policy name set.
      ApplicationPolicyBean bean = (ApplicationPolicyBean) super.getBean("TestPolicy2");
      assertNotNull("ApplicationPolicyBean not found", bean);
      assertNotNull("Parent policy name has not been set", bean.getParentPolicy());
      assertEquals("Unexpected parent policy name", "TestPolicy1", bean.getParentPolicy());

      // validate the real application policy has been created with the expected contents.
      ApplicationPolicy policy = XMLLoginConfigImpl.getInstance().getApplicationPolicy("TestPolicy2");
      assertNotNull("Application policy not found", policy);

      // validate the constructed authentication policy.
      PolicyValidator.validateAuthenticationPolicy("TestPolicy2", (AuthenticationInfo) policy.getAuthenticationInfo());
      // validate the constructed authorization policy.
      PolicyValidator.validateAuthorizationPolicy("TestPolicy2", policy.getAuthorizationInfo());
      // validate the constructed acl policy.
      PolicyValidator.validateACLPolicy("TestPolicy2", policy.getAclInfo());
      // validate the constructed role-mapping policy, whose configuration comes exclusively from the parent policy.
      PolicyValidator.validateRoleMappingPolicy("TestPolicy1", policy.getMappingInfo("role"));
      // validate the constructed audit policy.
      PolicyValidator.validateAuditPolicy("TestPolicy2", policy.getAuditInfo());
      // validate the constructed identity-trust policy.
      PolicyValidator.validateIdentityTrustPolicy("TestPolicy2", policy.getIdentityTrustInfo());

      // now validate the jaspi authentication extension.
      bean = (ApplicationPolicyBean) super.getBean("TestPolicy4");
      assertNotNull("ApplicationPolicyBean not found", bean);
      assertNotNull("Parent policy name has not been set", bean.getParentPolicy());
      assertEquals("Unexpected parent policy name", "TestPolicy3", bean.getParentPolicy());
      // validate the real application policy has been created with the expected contents.
      policy = XMLLoginConfigImpl.getInstance().getApplicationPolicy("TestPolicy4");
      assertNotNull("Application policy not found", policy);
      // validate the constructed jaspi authentication policy.
      PolicyValidator.validateJaspiAuthenticationPolicy("TestPolicy4", (JASPIAuthenticationInfo) policy
            .getAuthenticationInfo());
   }
}
