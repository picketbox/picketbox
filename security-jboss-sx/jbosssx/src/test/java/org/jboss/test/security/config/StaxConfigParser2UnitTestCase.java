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
package org.jboss.test.security.config;

import java.io.InputStream;
import java.util.List;
import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;

import junit.framework.Assert;
import junit.framework.TestCase;
import org.jboss.security.acl.config.ACLProviderEntry;
import org.jboss.security.audit.config.AuditProviderEntry;
import org.jboss.security.auth.container.config.AuthModuleEntry;
import org.jboss.security.auth.login.BaseAuthenticationInfo;
import org.jboss.security.auth.login.LoginModuleStackHolder;
import org.jboss.security.authorization.config.AuthorizationModuleEntry;
import org.jboss.security.config.ACLInfo;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.ApplicationPolicyRegistration;
import org.jboss.security.config.AuditInfo;
import org.jboss.security.config.AuthorizationInfo;
import org.jboss.security.config.ControlFlag;
import org.jboss.security.config.IdentityTrustInfo;
import org.jboss.security.config.MappingInfo;
import org.jboss.security.config.StandaloneConfiguration;
import org.jboss.security.config.parser.StaxBasedConfigParser;
import org.jboss.security.identitytrust.config.IdentityTrustModuleEntry;
import org.jboss.security.mapping.MappingType;
import org.jboss.security.mapping.config.MappingModuleEntry;

/**
 * Unit test the stax based config parser
 * @author Anil.Saldhana@redhat.com
 * @since Jan 22, 2010
 */
public class StaxConfigParser2UnitTestCase extends TestCase
{
   public StaxConfigParser2UnitTestCase(String name)
   {
      super(name);
   }

   public void testSecurityConfig5() throws Exception
   {
      Configuration.setConfiguration(StandaloneConfiguration.getInstance());
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      StaxBasedConfigParser parser = new StaxBasedConfigParser();
      try (InputStream is = tcl.getResourceAsStream("config/securityConfig5.xml")) {
         parser.schemaValidate(is);
      }
      
      try (InputStream is = tcl.getResourceAsStream("config/securityConfig5.xml")) {
         parser.parse2(is);
      }
      
      TestSecurityConfig5.validateJAASConfiguration();
      TestSecurityConfig5.validateJASPIConfiguration();
      TestSecurityConfig5.validateCompleteConfiguration();
      TestSecurityConfig5.validateApplicationPolicyExtension();
   }
   
   public void testIdentityTrustConfig() throws Exception
   {
      Configuration.setConfiguration(StandaloneConfiguration.getInstance());
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      StaxBasedConfigParser parser = new StaxBasedConfigParser();
      try (InputStream is = tcl.getResourceAsStream("config/identitytrust-config.xml")) {
         parser.schemaValidate(is);
      }
      
      try (InputStream is = tcl.getResourceAsStream("config/identitytrust-config.xml")) {
         parser.parse2(is);
      }
      
      TestIdentityTrustConfig.testConfJavaEE();
   }
   
   private static ApplicationPolicy getApplicationPolicy(String domainName)
   {
      Configuration config = Configuration.getConfiguration();
      if(config instanceof ApplicationPolicyRegistration == false)
         throw new RuntimeException("Config is not of type ApplicationPolicyRegistration");
      
      ApplicationPolicyRegistration apr = (ApplicationPolicyRegistration) config;
      return apr.getApplicationPolicy(domainName);
   }
   
   // Internal class to represent the securityConfig5.xml validation
   private static class TestSecurityConfig5
   { 
      public static void validateJAASConfiguration()
      {
         ApplicationPolicy jaasConfig = getApplicationPolicy("conf-jaas");
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

      public static void validateJASPIConfiguration()
      {
         ApplicationPolicy jaspiConfig = getApplicationPolicy("conf-jaspi");
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

      public static void validateCompleteConfiguration()
      {
         ApplicationPolicy completeConfig = getApplicationPolicy("conf-complete");
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

      public static void validateApplicationPolicyExtension()
      {
         ApplicationPolicy completeConfig = getApplicationPolicy("conf-jaas-extend");
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
         ApplicationPolicy jaspiPolicy = getApplicationPolicy("conf-jaspi-extend");
         assertNotNull("Unexpected null conf-jaspi-extend application policy", jaspiPolicy);
         BaseAuthenticationInfo authInfo = jaspiPolicy.getAuthenticationInfo();
         assertNotNull("Unexpected null jaspi configuration", authInfo);
         List<?> entries = authInfo.getModuleEntries();
         assertEquals("Invalid number of auth modules", 3, entries.size());
      } 
   } //End class TestSecurityConfig5
   
   
   //Validate the identitytrust-config.xml
   private static class TestIdentityTrustConfig
   {
      public static void testConfJavaEE()
      { 
         ApplicationPolicy javaeeConfig = getApplicationPolicy("conf-javaee");
         IdentityTrustInfo identityTrust = javaeeConfig.getIdentityTrustInfo();
         assertNotNull("IdentityTrustInfo", identityTrust);
         
         IdentityTrustModuleEntry[] itilist = identityTrust.getIdentityTrustModuleEntry();
         assertEquals("IdentityTrustModuleEntry length=1", 1, itilist.length); 
         
         IdentityTrustModuleEntry itme = itilist[0];
         assertEquals("org.jboss.security.identitytrust.modules.JavaEETrustModule", itme.getName());
      }
   }
   
}