/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2010, Red Hat Middleware LLC, and individual contributors
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
package org.jboss.test.authentication;

import java.lang.reflect.Method;
import java.security.Principal;
import java.security.acl.Group;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;

import junit.framework.TestCase;

import org.jboss.logging.Logger;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.SecurityContextFactory;
import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.UsernamePasswordLoginModule;
import org.jboss.security.plugins.JBossSecuritySubjectFactory;

/**
 * TestCase for {@link JBossSecuritySubjectFactory}.
 * 
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @version $Revision: 1 $
 */
public class JBossSecuritySubjectFactoryUnitTestCase extends TestCase
{

   private static Logger log = Logger.getLogger(JBossSecuritySubjectFactoryUnitTestCase.class);

   static class TestConfig extends Configuration
   {

      @Override
      public AppConfigurationEntry[] getAppConfigurationEntry(String name)
      {
         AppConfigurationEntry[] entry = null;
         try
         {
            Class[] parameterTypes = {};
            Method m = getClass().getDeclaredMethod(name, parameterTypes);
            Object[] args = {};
            entry = (AppConfigurationEntry[]) m.invoke(this, args);
         }
         catch (Exception e)
         {
         }
         return entry;
      }

      AppConfigurationEntry[] securityDomain()
      {
         AppConfigurationEntry ace = new AppConfigurationEntry(TestLoginModule2.class.getName(),
               AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, new HashMap<String, Object>());
         AppConfigurationEntry[] entry = {ace};
         return entry;
      }
      
      AppConfigurationEntry[] other()
      {
         AppConfigurationEntry ace = new AppConfigurationEntry(TestLoginModule1.class.getName(),
               AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, new HashMap<String, Object>());
         AppConfigurationEntry[] entry = {ace};
         return entry;
      }

   }
   
   public static class TestLoginModule1 extends UsernamePasswordLoginModule
   {
      @Override
      protected Group[] getRoleSets()
      {
         SimpleGroup roles = new SimpleGroup("Roles");
         Group[] roleSets = {roles};
         roles.addMember(new SimplePrincipal("TestRole"));
         roles.addMember(new SimplePrincipal("Role2"));
         return roleSets;
      }

      /** This represents the 'true' password
       */
      @Override
      protected String getUsersPassword()
      {
         return "secret";
      }
   }
   
   public static class TestLoginModule2 extends UsernamePasswordLoginModule
   {
      @Override
      protected Group[] getRoleSets()
      {
         SimpleGroup roles = new SimpleGroup("Roles");
         Group[] roleSets = {roles};
         roles.addMember(new SimplePrincipal("Role1"));
         return roleSets;
      }

      /** This represents the 'true' password
       */
      @Override
      protected String getUsersPassword()
      {
         return "verySecret";
      }
   }

   public JBossSecuritySubjectFactoryUnitTestCase(String testName)
   {
      super(testName);
   }

   @Override
   protected void setUp() throws Exception
   {
      // Install the custom JAAS configuration
      Configuration.setConfiguration(new TestConfig());
      super.setUp();
   }
   
   @Override
   protected void tearDown() throws Exception
   {
      super.tearDown();
      SecurityContextAssociation.setSecurityContext(null);
   }

   public void testSubjectCreationWithDefaultSecurityManagementImplementationAndSecurityDomain() throws Exception
   {
      log.info("testSubjectCreationWithDefaultSecurityManagementImplementationAndSecurityDomain");
      // setting SecurityContext
      SecurityContext sc = SecurityContextFactory.createSecurityContext("other");
      sc.getUtil().createSubjectInfo(new SimplePrincipal("scott"), "secret", new Subject());
      SecurityContextAssociation.setSecurityContext(sc);
      
      JBossSecuritySubjectFactory subjectFactory = new JBossSecuritySubjectFactory();
      Subject subject = subjectFactory.createSubject();
      Set<Group> groups = subject.getPrincipals(Group.class);
      Principal scott = new SimplePrincipal("scott");
      assertTrue("Principals contains scott", subject.getPrincipals().contains(scott));
      assertTrue("Principals contains Roles", groups.contains(new SimpleGroup("Roles")));
      assertTrue("Principals contains CallerPrincipal", groups.contains(new SimpleGroup("CallerPrincipal")));
      for (Group group : groups)
      {
         if (group.getName().equals("Roles"))
         {
            Enumeration<? extends Principal> roles = group.members();
            assertEquals("Roles group has 2 entries", 2, Collections.list(roles).size());
            assertTrue("TestRole is a role", group.isMember(new SimplePrincipal("TestRole")));
            assertTrue("Role2 is a role", group.isMember(new SimplePrincipal("Role2")));
         }
         else if (group.getName().equals("CallerPrincipal"))
         {
            Enumeration<? extends Principal> roles = group.members();
            assertEquals("CallerPrincipal group has 1 entry", 1, Collections.list(roles).size());
            assertTrue("scott is the caller principal", group.isMember(scott));
         }
         else
         {
            fail("Another group was set: " + group.getName());
         }
      }
   }
   
   public void testSubjectCreationWithDefaultSecurityManagementImplementation() throws Exception
   {
      log.info("testSubjectCreationWithDefaultSecurityManagementImplementation");
      // setting SecurityContext
      SecurityContext sc = SecurityContextFactory.createSecurityContext("securityDomain");
      sc.getUtil().createSubjectInfo(new SimplePrincipal("scott"), "verySecret", new Subject());
      SecurityContextAssociation.setSecurityContext(sc);
      
      JBossSecuritySubjectFactory subjectFactory = new JBossSecuritySubjectFactory();
      Subject subject = subjectFactory.createSubject("securityDomain");
      Set<Group> groups = subject.getPrincipals(Group.class);
      Principal scott = new SimplePrincipal("scott");
      assertTrue("Principals contains scott", subject.getPrincipals().contains(scott));
      assertTrue("Principals contains Roles", groups.contains(new SimpleGroup("Roles")));
      assertTrue("Principals contains CallerPrincipal", groups.contains(new SimpleGroup("CallerPrincipal")));
      for (Group group : groups)
      {
         if (group.getName().equals("Roles"))
         {
            Enumeration<? extends Principal> roles = group.members();
            assertEquals("Roles group has 1 entry", 1, Collections.list(roles).size());
            assertTrue("Role1 is a role", group.isMember(new SimplePrincipal("Role1")));
         }
         else if (group.getName().equals("CallerPrincipal"))
         {
            Enumeration<? extends Principal> roles = group.members();
            assertEquals("CallerPrincipal group has 1 entry", 1, Collections.list(roles).size());
            assertTrue("scott is the caller principal", group.isMember(scott));
         }
         else
         {
            fail("Another group was set: " + group.getName());
         }
      }
   }

}
