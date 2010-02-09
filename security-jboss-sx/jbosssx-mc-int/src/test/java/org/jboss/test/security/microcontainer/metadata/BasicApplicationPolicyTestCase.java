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

import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;

import junit.framework.Assert;

import org.jboss.security.SecurityConstants;
import org.jboss.security.auth.login.AuthenticationInfo;
import org.jboss.security.auth.login.JASPIAuthenticationInfo;
import org.jboss.security.auth.login.XMLLoginConfigImpl;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.microcontainer.beans.ApplicationPolicyBean;
import org.jboss.security.microcontainer.beans.AuthenticationPolicyBean;
import org.jboss.security.microcontainer.beans.JASPIAuthenticationPolicyBean;
import org.jboss.test.kernel.junit.MicrocontainerTest;
import org.jboss.xb.binding.sunday.unmarshalling.SingletonSchemaResolverFactory;

/**
 * <p>
 * This class tests the configuration of basic application policies. A basic application policy is one that declares
 * only the authentication information, using either an authentication or an authentication-jaspi sub-policy.
 * </p>
 * <p>
 * The first scenario tests the configuration of an application policy that declares an authentication sub-policy:
 * 
 * <pre>
 *  &lt;application-policy xmlns=&quot;urn:jboss:security-beans:1.0&quot; name=&quot;TestPolicy1&quot;&gt;
 *     &lt;authentication&gt;
 *        &lt;login-module code=&quot;org.jboss.security.auth.AuthModule1&quot; flag=&quot;required&quot;&gt;
 *           &lt;module-option name=&quot;authOption1&quot;&gt;value1&lt;/module-option&gt;
 *           &lt;module-option name=&quot;authOption2&quot;&gt;value2&lt;/module-option&gt;
 *        &lt;/login-module&gt;
 *        &lt;login-module code=&quot;org.jboss.security.auth.AuthModule2&quot; flag=&quot;optional&quot;&gt;
 *           &lt;module-option name=&quot;authOption3&quot;&gt;value3&lt;/module-option&gt;
 *           &lt;module-option name=&quot;authOption4&quot;&gt;value4&lt;/module-option&gt;
 *        &lt;/login-module&gt;
 *     &lt;/authentication&gt;
 *  &lt;/application-policy&gt;
 * </pre>
 * 
 * while the second scenario tests the configuration of an application policy that declares an authentication-jaspi
 * sub-policy:
 * 
 * <pre>
 *  &lt;application-policy xmlns=&quot;urn:jboss:security-beans:1.0&quot; name=&quot;TestPolicy2&quot;&gt;
 *     &lt;authentication-jaspi&gt;
 *        &lt;login-module-stack name=&quot;ModuleStack1&quot;&gt;
 *           &lt;login-module code=&quot;org.jboss.security.auth.AuthModule3&quot; flag=&quot;required&quot;&gt;
 *              &lt;module-option name=&quot;authOption5&quot;&gt;value5&lt;/module-option&gt;
 *           &lt;/login-module&gt;
 *           &lt;login-module code=&quot;org.jboss.security.auth.AuthModule4&quot; flag=&quot;optional&quot;/&gt;
 *        &lt;/login-module-stack&gt;
 *        &lt;login-module-stack name=&quot;ModuleStack2&quot;&gt;
 *           &lt;login-module code=&quot;org.jboss.security.auth.AuthModule5&quot; flag=&quot;required&quot;&gt;
 *              &lt;module-option name=&quot;authOption6&quot;&gt;value6&lt;/module-option&gt;
 *              &lt;module-option name=&quot;authOption7&quot;&gt;value7&lt;/module-option&gt;
 *           &lt;/login-module&gt;
 *        &lt;/login-module-stack&gt;
 *        &lt;auth-module code=&quot;org.jboss.security.auth.AuthModule1&quot; login-module-stack-ref=&quot;ModuleStack2&quot;&gt;
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
public class BasicApplicationPolicyTestCase extends MicrocontainerTest
{

   /**
    * <p>
    * Creates an instance of {@code BasicApplicationPolicyTestCase} with the specified name.
    * </p>
    * 
    * @param name a {@code String} representing the name of this test case.
    */
   public BasicApplicationPolicyTestCase(String name)
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
    * Tests the deployment of the basic application policies. This method first verifies that the expected beans have
    * been created by the {@code ApplicationPolicyMetaDataFactory} and validates the contents of those beans. It then
    * verifies that a corresponding {@code ApplicationPolicy} has been successfully generated by the beans and
    * registered with the security layer.
    * </p>
    * 
    * @throws Exception if an error occurs while running the test.
    */
   public void testApplicationPoliciesCreation() throws Exception
   {
      // validate the application policy beans have been properly created by the metadata factory.
      ApplicationPolicyBean policyBean1 = (ApplicationPolicyBean) super.getBean("TestPolicy1");
      assertNotNull("ApplicationPolicyBean TestPolicy1 not found", policyBean1);
      assertNotNull("Unexpected null authentication policy found", policyBean1.getAuthenticationPolicy());

      ApplicationPolicyBean policyBean2 = (ApplicationPolicyBean) super.getBean("TestPolicy2");
      assertNotNull("ApplicationPolicyBean TestPolicy2 not found", policyBean2);
      assertNotNull("Unexpected null jaspi authentication policy found", policyBean2.getAuthenticationPolicy());

      AuthenticationPolicyBean authBean = (AuthenticationPolicyBean) super.getBean("TestPolicy1$AuthenticationPolicy");
      // assert the bean retrieved from the microcontainer is the same that has been injected into the app policy.
      assertEquals(policyBean1.getAuthenticationPolicy(), authBean);
      BeanValidator.validateAuthenticationBean(authBean);

      JASPIAuthenticationPolicyBean jaspiAuthBean = (JASPIAuthenticationPolicyBean) super
            .getBean("TestPolicy2$JASPIAuthenticationPolicy");
      assertEquals(policyBean2.getAuthenticationPolicy(), jaspiAuthBean);
      BeanValidator.validateJaspiAuthenticationBean(jaspiAuthBean);

      // verify that the application policies have been created in the security layer and validate their contents.
      ApplicationPolicy policy1 = XMLLoginConfigImpl.getInstance().getApplicationPolicy("TestPolicy1");
      assertNotNull("Application policy TestPolicy1 not found", policy1);
      assertEquals("TestPolicy1", policy1.getName());
      PolicyValidator.validateAuthenticationPolicy("TestPolicy1", (AuthenticationInfo) policy1.getAuthenticationInfo());

      ApplicationPolicy policy2 = XMLLoginConfigImpl.getInstance().getApplicationPolicy("TestPolicy2");
      assertNotNull("Application policy TestPolicy2 not found", policy2);
      assertEquals("TestPolicy2", policy2.getName());
      PolicyValidator.validateJaspiAuthenticationPolicy("TestPolicy2", (JASPIAuthenticationInfo) policy2
            .getAuthenticationInfo());

      // check the contents of the array returned by XMLLoginConfigImpl.getAppConfigurationEntry.
      this.validateAppConfigurationEntryCreation();
   }

   /**
    * <p>
    * Tests the contents of the {@code AppConfigurationEntry} array that is returned by {@code XMLLoginConfigImpl}. This
    * method basically verifies if the entries returned by the {@code getAppConfigurationEntry} method corresponds to the
    * modules that have been specified in the application policy.
    * </p>
    * 
    * @throws Exception if an error occurs while running the test.
    */
   public void validateAppConfigurationEntryCreation() throws Exception
   {
      // validate the contents of the array returned by XMLLoginConfigImpl.getAppConfigurationEntry.
      AppConfigurationEntry[] entries = XMLLoginConfigImpl.getInstance().getAppConfigurationEntry("TestPolicy1");
      assertNotNull("Invalid null AppConfigurationEntry array found", entries);
      assertEquals("Invalind number of configuration entries", 2, entries.length);

      Assert.assertEquals("org.jboss.security.auth.AuthModule1", entries[0].getLoginModuleName());
      Assert.assertEquals(LoginModuleControlFlag.REQUIRED, entries[0].getControlFlag());
      Map<String, ?> options = entries[0].getOptions();
      Assert.assertNotNull("Unexpected null options map", options);
      Assert.assertTrue("Option authOption1 was not found", options.containsKey("authOption1"));
      Assert.assertEquals("value1", options.get("authOption1"));
      Assert.assertTrue("Option authOption2 was not found", options.containsKey("authOption2"));
      Assert.assertEquals("value2", options.get("authOption2"));
      // the options map should contain the SecurityConstants.SECURITY_DOMAIN_OPTION.
      assertTrue("Option jboss.security.security_domain was not found", options
            .containsKey(SecurityConstants.SECURITY_DOMAIN_OPTION));
      assertEquals("TestPolicy1", options.get(SecurityConstants.SECURITY_DOMAIN_OPTION));

      Assert.assertEquals("org.jboss.security.auth.AuthModule2", entries[1].getLoginModuleName());
      Assert.assertEquals(LoginModuleControlFlag.OPTIONAL, entries[1].getControlFlag());
      options = entries[1].getOptions();
      Assert.assertNotNull("Unexpected null options map", options);
      Assert.assertTrue("Option authOption3 was not found", options.containsKey("authOption3"));
      Assert.assertEquals("value3", options.get("authOption3"));
      Assert.assertTrue("Option authOption4 was not found", options.containsKey("authOption4"));
      Assert.assertEquals("value4", options.get("authOption4"));
      assertTrue("Option jboss.security.security_domain was not found", options
            .containsKey(SecurityConstants.SECURITY_DOMAIN_OPTION));
      assertEquals("TestPolicy1", options.get(SecurityConstants.SECURITY_DOMAIN_OPTION));

      // now check the contents of TestPolicy2 policy.
      entries = XMLLoginConfigImpl.getInstance().getAppConfigurationEntry("TestPolicy2");
      assertNotNull("Invalid null AppConfigurationEntry array found", entries);
      assertEquals("Invalind number of configuration entries", 2, entries.length);

      // getAppConfigurationEntry should return the modules of the first configured stack.
      assertEquals("org.jboss.security.auth.AuthModule3", entries[0].getLoginModuleName());
      assertEquals(LoginModuleControlFlag.REQUIRED, entries[0].getControlFlag());
      options = entries[0].getOptions();
      assertNotNull("Unexpected null options map", options);
      assertEquals(2, options.size());
      assertTrue("Option authOption5 was not found", options.containsKey("authOption5"));
      assertEquals("value5", options.get("authOption5"));
      assertTrue("Option jboss.security.security_domain was not found", options
            .containsKey(SecurityConstants.SECURITY_DOMAIN_OPTION));
      assertEquals("TestPolicy2", options.get(SecurityConstants.SECURITY_DOMAIN_OPTION));

      Assert.assertEquals("org.jboss.security.auth.AuthModule4", entries[1].getLoginModuleName());
      Assert.assertEquals(LoginModuleControlFlag.OPTIONAL, entries[1].getControlFlag());
      options = entries[1].getOptions();
      Assert.assertNotNull("Unexpected null options map", options);
      Assert.assertEquals(1, options.size());
      Assert.assertTrue("Option jboss.security.security_domain was not found", options
            .containsKey(SecurityConstants.SECURITY_DOMAIN_OPTION));
      Assert.assertEquals("TestPolicy2", options.get(SecurityConstants.SECURITY_DOMAIN_OPTION));
   }
}
