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
package org.jboss.test.security.mapping;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import javax.security.auth.login.Configuration;

import junit.framework.Test;
import junit.framework.TestSuite;

import org.jboss.security.SecurityConstants;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextFactory;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.login.XMLLoginConfigImpl;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.SecurityConfiguration;
import org.jboss.security.config.parser.StaxBasedConfigParser;
import org.jboss.security.identity.Attribute;
import org.jboss.security.mapping.MappingContext;
import org.jboss.security.mapping.MappingManager;
import org.jboss.security.mapping.MappingType;
import org.jboss.test.security.ldap.OpenDSUnitTestsAdapter;

/**
 * LdapAttributeMappingProvider tests
 * @author Anil.Saldhana@redhat.com
 */
public class LdapAttributeMappingProviderUnitTestCase extends OpenDSUnitTestsAdapter
{
   public static Test suite() throws Exception
   {
      TestSuite suite = new TestSuite();
      suite.addTest(new LdapAttributeMappingProviderUnitTestCase("testLDAPAttributes")); 
      suite.addTest(new LdapAttributeMappingProviderUnitTestCase("testLDAPMultiValueAttributes")); 
      return suite;
   }
   
   public LdapAttributeMappingProviderUnitTestCase(String name)
   {
      super(name); 
   }

   protected void setUp() throws Exception
   {
      super.setUp();
      XMLLoginConfigImpl xmlLogin = XMLLoginConfigImpl.getInstance();
      Configuration.setConfiguration(xmlLogin);
      
      ApplicationPolicy ap = new ApplicationPolicy("test"); 
      SecurityConfiguration.addApplicationPolicy(ap);
      
      //Let us add the ldapAttributes.ldif
      String fileName = targetDir + "ldap" + fs + "ldapAttributes.ldif";
      boolean op = util.addLDIF(serverHost, port, adminDN, adminPW, new File(fileName).toURI().toURL());
      assertTrue(op);
   }

   @Override
   public void tearDown() throws Exception {
      super.tearDown();
   }

   public void testLDAPAttributes() throws Exception
   {    
      StaxBasedConfigParser parser = new StaxBasedConfigParser();
      parser.parse(Thread.currentThread().getContextClassLoader().getResourceAsStream("ldap/ldap-attributes-config.xml"));
      
      SecurityContext sc = SecurityContextFactory.createSecurityContext("test");
      MappingManager mm = sc.getMappingManager();
      assertNotNull("MappingManager != null", mm);
      
      MappingContext<List<Attribute<String>>> mc = mm.getMappingContext(MappingType.ATTRIBUTE.name());
      assertNotNull("MappingContext != null", mc);
      assertEquals("1 module", 1,mc.getModules().size());
      HashMap<String,Object> map = new HashMap<String,Object>();
     
      map.put(SecurityConstants.PRINCIPAL_IDENTIFIER, new SimplePrincipal("jduke"));
      
      List<Attribute<String>> attList = new ArrayList<Attribute<String>>();
      
      mc.performMapping(map, attList);
      attList = (List<Attribute<String>>) mc.getMappingResult().getMappedObject(); 
      
      boolean foundEmail = false;
      boolean foundEmployeeType = false;
      boolean foundEmployeeNumber = false;
      
      assertNotNull("Attribute List is not null?", attList);
      
      for(Attribute<String> att: attList)
      {
         String attName = att.getName();
         if(attName.equals(Attribute.TYPE.EMAIL_ADDRESS.get()))
         {
            assertEquals("theduke@somecastle.man",att.getValue());
            foundEmail = true;
         }
         if(attName.equals("employeeType"))
         {
            assertEquals("permanent",att.getValue());
            foundEmployeeType = true;
         }
         if(attName.equals("employeeNumber"))
         {
            assertEquals("007",att.getValue());
            foundEmployeeNumber = true;
         }
      }
      assertTrue("Found Email", foundEmail);
      assertTrue("Found Emp Type", foundEmployeeType);
      assertTrue("Found Emp Number", foundEmployeeNumber);
   } 

   public void testLDAPMultiValueAttributes() throws Exception
   {    
      StaxBasedConfigParser parser = new StaxBasedConfigParser();
      parser.parse(Thread.currentThread().getContextClassLoader().getResourceAsStream("ldap/ldap-attributes-config.xml"));
      
      SecurityContext sc = SecurityContextFactory.createSecurityContext("test");
      MappingManager mm = sc.getMappingManager();
      assertNotNull("MappingManager != null", mm);
      
      MappingContext<List<Attribute<String>>> mc = mm.getMappingContext(MappingType.ATTRIBUTE.name());
      assertNotNull("MappingContext != null", mc);
      assertEquals("1 module", 1,mc.getModules().size());
      HashMap<String,Object> map = new HashMap<String,Object>();
     
      map.put(SecurityConstants.PRINCIPAL_IDENTIFIER, new SimplePrincipal("jduke"));
      
      List<Attribute<String>> attList = new ArrayList<Attribute<String>>();
      
      mc.performMapping(map, attList);
      attList = (List<Attribute<String>>) mc.getMappingResult().getMappedObject(); 
      
      boolean foundMobile1 = false;
      boolean foundMobile2 = false;
      boolean foundMobile3 = false;
      
      assertNotNull("Attribute List is not null?", attList);
      
      for(Attribute<String> att: attList)
      {
         String attName = att.getName();
         if(attName.equals("mobile"))
         {
           if( att.getValue().equals("1") )
             foundMobile1 = true;
           else if( att.getValue().equals("2") )
             foundMobile2 = true;
           else if( att.getValue().equals("3") )
             foundMobile3 = true;
         }
      }

      assertTrue("Found mobile1", foundMobile1);
      assertTrue("Found mobile2", foundMobile2);
      assertTrue("Found mobile3", foundMobile3);
   } 

}
