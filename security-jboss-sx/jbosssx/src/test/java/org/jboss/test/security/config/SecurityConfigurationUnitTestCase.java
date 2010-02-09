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
package org.jboss.test.security.config;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.List;
import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;

import junit.framework.Assert;

import org.jboss.security.acl.config.ACLProviderEntry;
import org.jboss.security.audit.config.AuditProviderEntry;
import org.jboss.security.auth.container.config.AuthModuleEntry;
import org.jboss.security.auth.login.BaseAuthenticationInfo;
import org.jboss.security.auth.login.LoginConfigObjectModelFactory;
import org.jboss.security.auth.login.LoginModuleStackHolder;
import org.jboss.security.auth.spi.UsersObjectModelFactory;
import org.jboss.security.authorization.config.AuthorizationModuleEntry;
import org.jboss.security.authorization.config.SecurityConfigObjectModelFactory;
import org.jboss.security.config.ACLInfo;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.AuditInfo;
import org.jboss.security.config.AuthorizationInfo;
import org.jboss.security.config.ControlFlag;
import org.jboss.security.config.IdentityTrustInfo;
import org.jboss.security.config.MappingInfo;
import org.jboss.security.config.PolicyConfig;
import org.jboss.security.config.SecurityConfiguration;
import org.jboss.security.identitytrust.config.IdentityTrustModuleEntry;
import org.jboss.security.mapping.MappingType;
import org.jboss.security.mapping.config.MappingModuleEntry;
import org.jboss.test.AbstractJBossSXTest;
import org.jboss.xb.binding.Unmarshaller;
import org.jboss.xb.binding.UnmarshallerFactory;

/**
 * Security Configuration Unit Test Case
 * 
 * @author Anil.Saldhana@redhat.com
 * @since Jul 25, 2007
 * @version $Revision$
 */
public class SecurityConfigurationUnitTestCase extends AbstractJBossSXTest
{
   protected String schemaFile = "schema/security-config_5_0.xsd";

   protected String xmlFile = "config/securityConfig5.xml";

   protected PolicyConfig config = null;

   public SecurityConfigurationUnitTestCase(String name)
   {
      super(name);
   }

   @Override
   protected void setUp() throws Exception
   {
      super.setUp();
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();

      LoginConfigObjectModelFactory lcomf = new SecurityConfigObjectModelFactory();
      UsersObjectModelFactory uomf = new UsersObjectModelFactory();
      URL xmlFileURL = tcl.getResource(xmlFile);
      assertNotNull("XML File URL is not null", xmlFileURL);
      InputStreamReader xmlReader = loadURL(xmlFileURL);
      Unmarshaller unmarshaller = UnmarshallerFactory.newInstance().newUnmarshaller();
      unmarshaller.mapFactoryToNamespace(uomf, "http://www.jboss.org/j2ee/schemas/XMLLoginModule");
      unmarshaller.setSchemaValidation(true);
      unmarshaller.setNamespaceAware(true);
      unmarshaller.setFeature(Unmarshaller.SCHEMA_VALIDATION, Boolean.TRUE);
      Object root = null;
      config = (PolicyConfig) unmarshaller.unmarshal(xmlReader, lcomf, root);
      assertNotNull("PolicyConfig is not null", config);
   }

   public void testValidateJAASConfiguration()
   {
      ApplicationPolicy jaasConfig = config.get("conf-jaas");
      BaseAuthenticationInfo authInfo = jaasConfig.getAuthenticationInfo();
      List<?> entries = authInfo.getModuleEntries();
      assertEquals("Number of entries = 2", 2, entries.size());

      // First Entry
      Object entry = entries.get(0);
      assertTrue("Entry instanceof AppConfigurationEntry", entry instanceof AppConfigurationEntry);
      AppConfigurationEntry ace = (AppConfigurationEntry) entry;
      assertEquals("LM Name", "org.jboss.test.TestLoginModule", ace.getLoginModuleName());
      assertEquals("Required", AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, ace.getControlFlag());
      Map<String, ?> aceOptions = ace.getOptions();
      assertEquals("Number of options = 3", 3, aceOptions.size());
      assertEquals("name=1.1", "1.1", aceOptions.get("name"));
      assertEquals("succeed=true", "true", aceOptions.get("succeed"));
      assertEquals("throwEx=false", "false", aceOptions.get("throwEx"));

      // Second Entry
      entry = entries.get(1);
      assertTrue("Entry instanceof AppConfigurationEntry", entry instanceof AppConfigurationEntry);
      ace = (AppConfigurationEntry) entry;
      assertEquals("LM Name", "org.jboss.test.TestLoginModule2", ace.getLoginModuleName());
      assertEquals("Optional expected", AppConfigurationEntry.LoginModuleControlFlag.OPTIONAL, ace.getControlFlag());
      aceOptions = ace.getOptions();
      assertEquals("Number of options = 4", 4, aceOptions.size());
      assertEquals("name=1.2", "1.2", aceOptions.get("name"));
      assertEquals("succeed=false", "false", aceOptions.get("succeed"));
      assertEquals("throwEx=true", "true", aceOptions.get("throwEx"));
      assertEquals("dummy=d", "d", aceOptions.get("dummy"));

   }

   public void testValidateJASPIConfiguration()
   {
      ApplicationPolicy jaspiConfig = config.get("conf-jaspi");
      BaseAuthenticationInfo authInfo = jaspiConfig.getAuthenticationInfo();
      List<?> entries = authInfo.getModuleEntries();
      assertEquals("Number of entries = 2", 2, entries.size());

      // First Entry
      Object entry = entries.get(0);
      assertTrue("Entry instanceof AppConfigurationEntry", entry instanceof AuthModuleEntry);
      AuthModuleEntry ace = (AuthModuleEntry) entry;
      assertEquals("LM Name", "TestAuthModule", ace.getAuthModuleName());
      assertEquals("Required", ControlFlag.REQUIRED, ace.getControlFlag());
      Map<String, ?> aceOptions = ace.getOptions();
      assertEquals("Number of options = 3", 3, aceOptions.size());
      assertEquals("usersProperties=u", "u", aceOptions.get("usersProperties"));
      assertEquals("rolesProperties=r", "r", aceOptions.get("rolesProperties"));
      assertEquals("unauthenticatedIdentity=anonymous", "anonymous", aceOptions.get("unauthenticatedIdentity"));

      // Second Entry
      entry = entries.get(1);
      assertTrue("Entry instanceof AppConfigurationEntry", entry instanceof AuthModuleEntry);
      ace = (AuthModuleEntry) entry;
      assertEquals("LM Name", "TestAuthModule2", ace.getAuthModuleName());
      assertEquals("Required", ControlFlag.REQUIRED, ace.getControlFlag());
      aceOptions = ace.getOptions();
      assertEquals("Number of options = 0", 0, aceOptions.size());
      LoginModuleStackHolder lmsh = ace.getLoginModuleStackHolder();
      assertEquals("lm-stack", "lm-stack", lmsh.getName());
      AppConfigurationEntry[] appEntries = lmsh.getAppConfigurationEntry();
      assertEquals("App Entries in LMSH=1", 1, appEntries.length);

      Object appEntry = appEntries[0];
      assertTrue("Entry instanceof AppConfigurationEntry", appEntry instanceof AppConfigurationEntry);
      AppConfigurationEntry appace = (AppConfigurationEntry) appEntry;
      assertEquals("LM Name", "org.jboss.security.auth.spi.UsersRolesLoginModule", appace.getLoginModuleName());
      assertEquals("Optional", AppConfigurationEntry.LoginModuleControlFlag.OPTIONAL, appace.getControlFlag());
      Map<String, ?> appaceOptions = appace.getOptions();
      assertEquals("Number of options = 3", 3, appaceOptions.size());
      assertEquals("usersProperties=u", "u", appaceOptions.get("usersProperties"));
      assertEquals("rolesProperties=r", "r", appaceOptions.get("rolesProperties"));
      assertEquals("unauthenticatedIdentity=anonymous", "anonymous", appaceOptions.get("unauthenticatedIdentity"));
   }

   public void testValidateCompleteConfiguration()
   {
      ApplicationPolicy completeConfig = config.get("conf-complete");
      BaseAuthenticationInfo authInfo = completeConfig.getAuthenticationInfo();
      List<?> entries = authInfo.getModuleEntries();
      assertEquals("Number of entries = 1", 1, entries.size());

      // First Entry
      Object entry = entries.get(0);
      assertTrue("Entry instanceof AppConfigurationEntry", entry instanceof AppConfigurationEntry);
      AppConfigurationEntry ace = (AppConfigurationEntry) entry;
      assertEquals("LM Name", "org.jboss.test.TestLoginModule", ace.getLoginModuleName());
      assertEquals("Required", AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, ace.getControlFlag());
      Map<String, ?> aceOptions = ace.getOptions();
      assertEquals("Number of options = 3", 3, aceOptions.size());
      assertEquals("name=1.1", "1.1", aceOptions.get("name"));
      assertEquals("succeed=true", "true", aceOptions.get("succeed"));
      assertEquals("throwEx=false", "false", aceOptions.get("throwEx"));

      // Authorization
      AuthorizationInfo authzInfo = completeConfig.getAuthorizationInfo();
      assertNotNull("AuthorizationInfo is not null", authzInfo);
      AuthorizationModuleEntry[] authzEntries = authzInfo.getAuthorizationModuleEntry();
      assertEquals("Length of authorization entries = 1", 1, authzEntries.length);
      AuthorizationModuleEntry authzEntry = authzEntries[0];
      assertEquals("TestPolicyModule", "org.jboss.test.TestPolicyModule", authzEntry.getPolicyModuleName());
      assertEquals("Required", ControlFlag.REQUIRED, authzEntry.getControlFlag());
      Map<String, ?> authzoptions = authzEntry.getOptions();
      assertEquals("Number of options = 2", 2, authzoptions.size());
      assertEquals("name=authz", "authz", authzoptions.get("name"));
      assertEquals("succeed=true", "true", authzoptions.get("succeed"));

      // ACL (instance-based authorization)
      ACLInfo aclInfo = completeConfig.getAclInfo();
      assertNotNull("Unexpected null ACLInfo found", aclInfo);
      ACLProviderEntry[] aclEntries = aclInfo.getACLProviderEntry();
      assertNotNull("Unexpected null set of acl entries", aclEntries);
      assertEquals("Invalid number of acl entries", 2, aclEntries.length);
      // first entry should be org.jboss.security.authz.ACLModule1.
      Assert.assertEquals("org.jboss.security.authz.ACLModule1", aclEntries[0].getAclProviderName());
      Assert.assertEquals("REQUIRED", aclEntries[0].getControlFlag().toString());
      Map<String, ?> options = aclEntries[0].getOptions();
      Assert.assertNotNull("Unexpected null options map", options);
      Assert.assertTrue("Option aclOption1 was not found", options.containsKey("aclOption1"));
      Assert.assertEquals("value1", options.get("aclOption1"));
      Assert.assertTrue("Option aclOption2 was not found", options.containsKey("aclOption2"));
      Assert.assertEquals("value2", options.get("aclOption2"));
      // second entry should be the org.jboss.security.authz.ACLModule2.
      Assert.assertEquals("org.jboss.security.authz.ACLModule2", aclEntries[1].getAclProviderName());
      Assert.assertEquals("REQUIRED", aclEntries[1].getControlFlag().toString());
      options = aclEntries[1].getOptions();
      Assert.assertNotNull("Unexpected null options map", options);
      Assert.assertTrue("Option aclOption3 was not found", options.containsKey("aclOption3"));
      Assert.assertEquals("value3", options.get("aclOption3"));
      Assert.assertTrue("Option aclOption4 was not found", options.containsKey("aclOption4"));
      Assert.assertEquals("value4", options.get("aclOption4"));

      // Mapping
      MappingInfo mappingInfo = completeConfig.getMappingInfo(MappingType.PRINCIPAL.toString());
      assertNotNull("MappingInfo is not null", mappingInfo);
      MappingModuleEntry[] mappingEntries = mappingInfo.getMappingModuleEntry();
      assertEquals("Invalid number of entries", 1, mappingEntries.length);
      MappingModuleEntry mappingEntry = mappingEntries[0];
      assertEquals("org.jboss.test.mapping.MappingModule1", mappingEntry.getMappingModuleName());
      Map<String, ?> mappingOptions = mappingEntry.getOptions();
      assertEquals("Invalid number of options", 1, mappingOptions.size());
      Assert.assertTrue("Option option1 was not found", mappingOptions.containsKey("option1"));
      assertEquals("value1", mappingOptions.get("option1"));

      // Role Mapping
      mappingInfo = completeConfig.getMappingInfo(MappingType.ROLE.toString());
      assertNotNull("MappingInfo is not null", mappingInfo);
      MappingModuleEntry[] mmearr = mappingInfo.getMappingModuleEntry();
      assertEquals("Mapping entry length=1", 1, mmearr.length);
      MappingModuleEntry mme = mmearr[0];
      assertEquals("TestMappingModule", "org.jboss.test.TestMappingModule", mme.getMappingModuleName());
      Map<String, ?> mmOptions = mme.getOptions();
      assertEquals("Number of options = 2", 2, mmOptions.size());
      assertEquals("name=rolemap", "rolemap", mmOptions.get("name"));
      assertEquals("succeed=true", "true", mmOptions.get("succeed"));

      // Audit
      AuditInfo ai = completeConfig.getAuditInfo();
      assertNotNull("AuditInfo", ai);
      AuditProviderEntry[] apelist = ai.getAuditProviderEntry();
      assertEquals("Audit entry length=1", 1, apelist.length);
      AuditProviderEntry ape = apelist[0];
      assertEquals("TestMappingModule", "org.jboss.test.TestMappingModule", mme.getMappingModuleName());
      Map<String, ?> auditOptions = ape.getOptions();
      assertEquals("Number of options = 2", 2, auditOptions.size());
      assertEquals("name=auditprovider", "auditprovider", auditOptions.get("name"));
      assertEquals("succeed=false", "false", auditOptions.get("succeed"));

      // Identity Trust
      IdentityTrustInfo iti = completeConfig.getIdentityTrustInfo();
      assertNotNull("IdentityTrustInfo", iti);
      IdentityTrustModuleEntry[] itilist = iti.getIdentityTrustModuleEntry();
      assertEquals("IdentityTrustModuleEntry length=1", 1, itilist.length);
      IdentityTrustModuleEntry itie = itilist[0];
      assertEquals("TestMappingModule", "org.jboss.test.TestMappingModule", mme.getMappingModuleName());
      Map<String, ?> itieOptions = itie.getOptions();
      assertEquals("Number of options = 3", 3, itieOptions.size());
      assertEquals("name=trustprovider", "trustprovider", itieOptions.get("name"));
      assertEquals("succeed=true", "true", itieOptions.get("succeed"));
      assertEquals("dummy=dr", "dr", itieOptions.get("dummy"));
   }

   public void testApplicationPolicyExtension()
   {
      ApplicationPolicy completeConfig = config.get("conf-jaas-extend");
      assertNotNull("conf-jaas-extend is not null", completeConfig);
      BaseAuthenticationInfo bai = completeConfig.getAuthenticationInfo();
      assertNotNull("BaseAuthenticationInfo is not null", bai);
      assertEquals("3 login modules", 3, bai.getModuleEntries().size());

      // Authorization
      AuthorizationInfo azi = completeConfig.getAuthorizationInfo();
      assertNotNull("AuthorizationInfo is not null", azi);
      assertEquals("3 authz modules", 3, azi.getModuleEntries().size());

      // ACL
      ACLInfo aclInfo = completeConfig.getAclInfo();
      assertNotNull("Unexpected null ACLInfo", aclInfo);
      assertEquals("Unexpected number of acl modules", 3, aclInfo.getModuleEntries().size());

      // Role Mapping
      MappingInfo mappingInfo = completeConfig.getMappingInfo(MappingType.ROLE.toString());
      assertNotNull("MappingInfo is not null", mappingInfo);
      // we expect 2 modules because one has been configured as a mapping of type "role"
      assertEquals("2 map modules", 2, mappingInfo.getModuleEntries().size());

      // Mapping
      mappingInfo = completeConfig.getMappingInfo(MappingType.PRINCIPAL.toString());
      assertNotNull("MappingInfo is not null", mappingInfo);
      MappingModuleEntry[] mappingEntries = mappingInfo.getMappingModuleEntry();
      assertEquals("Invalid number of entries", 2, mappingEntries.length);
      assertEquals("org.jboss.test.mapping.MappingModule1", mappingEntries[0].getMappingModuleName());
      assertEquals("org.jboss.test.mapping.MappingModule3", mappingEntries[1].getMappingModuleName());
      // same test as above: we expect 2 role-mapping modules: 1 from rolemapping and 1 from mapping with type "role".
      mappingInfo = completeConfig.getMappingInfo(MappingType.ROLE.toString());
      assertNotNull("MappingInfo is not null", mappingInfo);
      mappingEntries = mappingInfo.getMappingModuleEntry();
      assertEquals("Invalid number of entries", 2, mappingEntries.length);
      assertEquals("org.jboss.test.TestMappingModule", mappingEntries[0].getMappingModuleName());
      assertEquals("org.jboss.test.mapping.MappingModule2", mappingEntries[1].getMappingModuleName());

      // Audit
      AuditInfo ai = completeConfig.getAuditInfo();
      assertNotNull("AuditInfo", ai);
      AuditProviderEntry[] apelist = ai.getAuditProviderEntry();
      assertEquals("Audit entry length=1", 1, apelist.length);

      // Identity Trust
      IdentityTrustInfo iti = completeConfig.getIdentityTrustInfo();
      assertNotNull("IdentityTrustInfo", iti);
      IdentityTrustModuleEntry[] itilist = iti.getIdentityTrustModuleEntry();
      assertEquals("IdentityTrustModuleEntry length=1", 1, itilist.length);

      // JASPI authentication policy extension
      ApplicationPolicy jaspiPolicy = config.get("conf-jaspi-extend");
      assertNotNull("Unexpected null conf-jaspi-extend application policy", jaspiPolicy);
      BaseAuthenticationInfo authInfo = jaspiPolicy.getAuthenticationInfo();
      assertNotNull("Unexpected null jaspi configuration", authInfo);
      List<?> entries = authInfo.getModuleEntries();
      assertEquals("Invalid number of auth modules", 3, entries.size());
   }

   public void testAddDeletionOfApplicationPolicies()
   {
      ApplicationPolicy aPolicy = new ApplicationPolicy("test");
      SecurityConfiguration.addApplicationPolicy(aPolicy);
      ApplicationPolicy ap = SecurityConfiguration.getApplicationPolicy("test");
      assertNotNull("Application Policy for test != null", ap);
      assertEquals("Application Policy Name = test", "test", ap.getName());

      SecurityConfiguration.removeApplicationPolicy("test");
      assertNull("Application Policy for test is null", SecurityConfiguration.getApplicationPolicy("test"));
   }

   private InputStreamReader loadURL(URL configURL) throws IOException
   {
      InputStream is = configURL.openStream();
      if (is == null)
         throw new IOException("Failed to obtain InputStream from url: " + configURL);
      InputStreamReader xmlReader = new InputStreamReader(is);
      return xmlReader;
   }
}