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
package org.jboss.test.authentication.jaas;

import java.io.File;
import java.util.HashMap;
import javax.management.MBeanServer;
import javax.management.MBeanServerFactory;
import javax.management.ObjectName;
import javax.naming.Context;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;

import org.jboss.security.auth.callback.AppCallbackHandler;
import org.jboss.security.auth.spi.LdapLoginModule;
import org.jboss.security.util.MBeanServerLocator;
import org.jboss.test.security.ldap.OpenDSUnitTestCase;

/**
 * SECURITY-426: DecodeAction is not using JaasSecurityDomain MBean
 * @author Anil.Saldhana@redhat.com
 */
public class LdapLoginModuleDecodeActionUnitTestCase extends OpenDSUnitTestCase
{ 
   private String oname = "jboss.test:service=jaasSecurityDomain";
   
   public LdapLoginModuleDecodeActionUnitTestCase(String name)
   {
      super(name); 
   }


   @SuppressWarnings("deprecation")
   @Override
   protected void setUp() throws Exception
   {
      super.setUp();
      //load it up with example1.ldif
      String fileName = targetDir + "ldap" + fs + "example1.ldif";
      boolean op = util.addLDIF(serverHost, port, adminDN, adminPW, new File(fileName).toURL());
      assertTrue(op);
      
      //Setup a configuration
      Configuration.setConfiguration(new Configuration() 
      {
         @SuppressWarnings("unchecked")
         @Override
         public AppConfigurationEntry[] getAppConfigurationEntry(String cname)
         {
            String name = LdapLoginModule.class.getName();
            HashMap options = new HashMap();
            
            options.put("java.naming.factory.initial", ldapCtxFactory);
            options.put("java.naming.provider.url","ldap://localhost:10389/");
            options.put("java.naming.security.authentication","simple");
            options.put("principalDNPrefix","uid=");
            options.put("uidAttributeID","userid");
            options.put("roleAttributeID","roleName");
            options.put("principalDNSuffix",",ou=People,dc=jboss,dc=org");
            options.put("rolesCtxDN","cn=JBossSX Tests,ou=Roles,dc=jboss,dc=org");
            options.put(Context.SECURITY_CREDENTIALS, "somecrazyencryptedstring");
            options.put("jaasSecurityDomain", oname);
            
            
            AppConfigurationEntry ace = new AppConfigurationEntry(name,
            AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
            AppConfigurationEntry[] entry = {ace};
            return entry; 
         }

         @Override
         public void refresh()
         {      
         }
      });
      
      //Setup MBeanServer
      MBeanServer jbossMBeanServer = MBeanServerFactory.createMBeanServer("jboss");
      MBeanServerLocator.setJBoss(jbossMBeanServer); 
      try
      {
         Test test = new Test();
         jbossMBeanServer.registerMBean(test, new ObjectName(oname)); 
      }
      catch(Exception e)
      {
         e.printStackTrace();
      }
   }

   @Override
   public void tearDown() throws Exception {
      super.tearDown();
   }
   
   public void testLDAPAddDelete() throws Exception
   {
      //Ignore
   }   
   
   public void testLDAPDecodeAction() throws Exception
   {
      LoginContext lc = new LoginContext("test", new AppCallbackHandler("jduke","theduke".toCharArray()));
      lc.login();
   }
   
   //We create a MBean that has just one operation for testing purposes
   public interface TestMBean
   {
      byte[] decode64(String secret) throws Exception;
   }
   
   public class Test implements TestMBean
   {
      public Test() 
      {   
      }
      
      //In JBoss environment, the JaasSecurityDomain mbean will perform the decoding
      public byte[] decode64(String secret) throws Exception
      {
         return "theduke".getBytes();
      }      
   }
}
