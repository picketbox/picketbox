/*
  * JBoss, Home of Professional Open Source
  * Copyright 2005, JBoss Inc., and individual contributors as indicated
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
package org.jboss.test.authentication.jaas;

import java.lang.reflect.Method;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashMap;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.SecurityContextFactory;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.SubjectInfo;
import org.jboss.security.auth.callback.UsernamePasswordHandler;

/**
 ClientLoginModuleUnitTestCase/SecurityContextAssociation interaction tests
 
 @author Scott.Stark@jboss.org
 @version $Revision: 68075 $
*/
public class ClientLoginModuleUnitTestCase
   extends TestCase
{
   static TestConfig jaasConfig = new TestConfig();

   static class TestConfig extends Configuration
   {
      public void refresh()
      {
      }

      public AppConfigurationEntry[] getAppConfigurationEntry(String name)
      {
         AppConfigurationEntry[] entry = null;
         try
         {
            Class<?>[] parameterTypes = {};
            Method m = getClass().getDeclaredMethod(name, parameterTypes);
            Object[] args = {};
            entry = (AppConfigurationEntry[]) m.invoke(this, args);
         }
         catch(Exception e)
         {
         }
         return entry;
      }
      AppConfigurationEntry[] testSingleThreaded()
      {
         String name = "org.jboss.security.ClientLoginModule";
         HashMap<String,String> options = new HashMap<String,String>();
         options.put("multi-threaded", "false");
         AppConfigurationEntry ace = new AppConfigurationEntry(name,
         AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
         AppConfigurationEntry[] entry = {ace};
         return entry;
      }
      AppConfigurationEntry[] testSingleThreadedRestoreIdentity()
      {
         String name = "org.jboss.security.ClientLoginModule";
         HashMap<String,String> options = new HashMap<String,String>();
         options.put("multi-threaded", "false");
         options.put("restore-login-identity", "true");
         AppConfigurationEntry ace = new AppConfigurationEntry(name,
         AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
         AppConfigurationEntry[] entry = {ace};
         return entry;
      }
      AppConfigurationEntry[] testSingleThreadedRestoreStack()
      {
         String name = "org.jboss.security.ClientLoginModule";
         HashMap<String,String> options = new HashMap<String,String>();
         options.put("multi-threaded", "false");
         options.put("restore-login-identity", "true");
         AppConfigurationEntry ace = new AppConfigurationEntry(name,
         AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
         AppConfigurationEntry[] entry = {ace};
         return entry;
      }
      AppConfigurationEntry[] testMultiThreaded()
      {
         String name = "org.jboss.security.ClientLoginModule";
         HashMap<String,String> options = new HashMap<String,String>();
         options.put("multi-threaded", "true");
         AppConfigurationEntry ace = new AppConfigurationEntry(name,
         AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
         AppConfigurationEntry[] entry = {ace};
         return entry;
      }
      AppConfigurationEntry[] testMultiThreadedRestoreIdentity()
      {
         String name = "org.jboss.security.ClientLoginModule";
         HashMap<String,String> options = new HashMap<String,String>();
         options.put("multi-threaded", "true");
         options.put("restore-login-identity", "true");
         AppConfigurationEntry ace = new AppConfigurationEntry(name,
         AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
         AppConfigurationEntry[] entry = {ace};
         return entry;
      }
      AppConfigurationEntry[] testMultiThreadedRestoreStack()
      {
         String name = "org.jboss.security.ClientLoginModule";
         HashMap<String,String> options = new HashMap<String,String>();
         options.put("multi-threaded", "true");
         options.put("restore-login-identity", "true");
         AppConfigurationEntry ace = new AppConfigurationEntry(name,
         AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
         AppConfigurationEntry[] entry = {ace};
         return entry;
      }
       
      AppConfigurationEntry[] testAbortWithRestore()
      {
         String name1 = "org.jboss.security.auth.spi.SimpleServerLoginModule";
         AppConfigurationEntry ace1 = new AppConfigurationEntry(name1,
         AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, new HashMap<String,String>()); 
         
         
         String name2 = "org.jboss.security.ClientLoginModule";
         HashMap<String,String> options = new HashMap<String,String>();
         options.put("multi-threaded", "true"); 
         options.put("restore-login-identity", "true");
         
         
         AppConfigurationEntry ace2 = new AppConfigurationEntry(name2,
         AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
         
         AppConfigurationEntry[] entry = {ace1,ace2};
         return entry; 
      }
       
      AppConfigurationEntry[] testAbortWithNoRestore()
      {
         String name1 = "org.jboss.security.auth.spi.SimpleServerLoginModule";
         AppConfigurationEntry ace1 = new AppConfigurationEntry(name1,
         AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, new HashMap<String,String>()); 
         
         
         String name2 = "org.jboss.security.ClientLoginModule";
         HashMap<String,String> options = new HashMap<String,String>();
         options.put("multi-threaded", "true"); 
         
         AppConfigurationEntry ace2 = new AppConfigurationEntry(name2,
         AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
         
         AppConfigurationEntry[] entry = {ace1,ace2};
         return entry; 
      }
      
   }

   public static Test suite() throws Exception
   {
      TestSuite suite = new TestSuite();
      suite.addTest(new ClientLoginModuleUnitTestCase("testSingleThreaded"));
      suite.addTest(new ClientLoginModuleUnitTestCase("testSingleThreadedRestoreIdentity"));
      suite.addTest(new ClientLoginModuleUnitTestCase("testMultiThreaded"));
      suite.addTest(new ClientLoginModuleUnitTestCase("testMultiThreadedRestoreIdentity"));
      suite.addTest(new ClientLoginModuleUnitTestCase("testAbortWithRestore"));
      suite.addTest(new ClientLoginModuleUnitTestCase("testAbortWithNoRestore"));
      return suite;
   }

   public ClientLoginModuleUnitTestCase(String name)
   {
      super(name);
   }

   protected void setUp() throws Exception
   {
      Configuration.setConfiguration(jaasConfig);
      //Clear SecurityContextAssociation
      SecurityContextAssociation.clearSecurityContext();
   }
   protected void tearDown()
   {
   }

   public void testSingleThreaded() throws Exception
   {
      System.out.println("+++ testSingleThreaded");
      UsernamePasswordHandler handler = new UsernamePasswordHandler("jduke",
         "theduke");
      LoginContext lc = new LoginContext("testSingleThreaded", handler);
      lc.login();
      Subject subject = lc.getSubject();
      System.out.println("LC.Subject: "+subject);
      Principal theduke = new SimplePrincipal("jduke");
      assertTrue("Principals contains theduke", subject.getPrincipals().contains(theduke));
      Principal saPrincipal = SecurityContextAssociation.getPrincipal();
      assertTrue("SecurityContextAssociation.getPrincipal == theduke", saPrincipal.equals(theduke));
      char[] password = (char[]) SecurityContextAssociation.getCredential();
      assertTrue("password == theduke",
         Arrays.equals(password, "theduke".toCharArray()));
      
      assertTrue("Client side association?", SecurityContextAssociation.isClient());
      
      SecurityContext sc = SecurityContextAssociation.getSecurityContext();
      assertNotNull("SecurityContext not null", sc);
      assertEquals("jduke", sc.getUtil().getUserPrincipal().getName()); 
   }

   public void testSingleThreadedRestoreIdentity() throws Exception
   {
      System.out.println("+++ testSingleThreadedRestoreIdentity");
      
      Principal jduke1 = new SimplePrincipal("jduke1");
      SecurityContext sc = SecurityContextAssociation.getSecurityContext();
      if (sc == null)
         sc = SecurityContextFactory.createSecurityContext("test");
      sc.getUtil().createSubjectInfo(jduke1, "theduke1", new Subject());
      SecurityContextAssociation.setSecurityContext(sc);

      UsernamePasswordHandler handler = new UsernamePasswordHandler("jduke2",
         "theduke2");
      LoginContext lc = new LoginContext("testSingleThreadedRestoreIdentity", handler);
      lc.login();
      Subject subject = lc.getSubject();
      System.out.println("LC.Subject: "+subject);
      
      Principal jduke2 = new SimplePrincipal("jduke2");
      assertTrue("Principals contains jduke2", subject.getPrincipals().contains(jduke2));
      Principal saPrincipal = SecurityContextAssociation.getPrincipal();
      assertTrue("SecurityContextAssociation.getPrincipal == jduke2", saPrincipal.equals(jduke2));
      char[] password = (char[]) SecurityContextAssociation.getCredential();
      assertTrue("password == theduke2",
         Arrays.equals(password, "theduke2".toCharArray()));

      lc.logout();
      // Validate restored state
      saPrincipal = SecurityContextAssociation.getPrincipal();
      assertTrue("SecurityContextAssociation.getPrincipal == jduke1", saPrincipal.equals(jduke1));
      String theduke1 = (String) SecurityContextAssociation.getCredential();
      assertTrue("password == theduke1", theduke1.equals("theduke1"));
      
   }

   public void testMultiThreaded() throws Exception
   {
      TestMultiThreaded r0 = new TestMultiThreaded();
      Thread t0 = new Thread(r0, "testMultiThreaded#0");
      t0.start();
      TestMultiThreaded r1 = new TestMultiThreaded();
      Thread t1 = new Thread(r1, "testMultiThreaded#1");
      t1.start();

      t0.join();
      assertTrue(r0.failure == null);
      t1.join();
      assertTrue(r1.failure == null);
   }
   static class TestMultiThreaded implements Runnable
   {
      Exception failure;
      public void run()
      {
         try
         {
            System.out.println("+++ testMultiThreadedRunnable");
            UsernamePasswordHandler handler = new UsernamePasswordHandler("jduke",
               "theduke");
            LoginContext lc = new LoginContext("testMultiThreaded", handler);
            lc.login();
            Subject subject = lc.getSubject();
            System.out.println("LC.Subject: "+subject);
            Principal theduke = new SimplePrincipal("jduke");
            assertTrue("Principals contains theduke", subject.getPrincipals().contains(theduke));
            Principal saPrincipal = SecurityContextAssociation.getPrincipal();
            assertTrue("SecurityContextAssociation.getPrincipal == theduke", saPrincipal.equals(theduke));
            char[] password = (char[]) SecurityContextAssociation.getCredential();
            assertTrue("password == theduke",
               Arrays.equals(password, "theduke".toCharArray()));
         }
         catch(Exception e)
         {
            failure = e;
         }
      }
   }

   public void testMultiThreadedRestoreIdentity() throws Exception
   {
      TestMultiThreadedRestoreIdentity r0 = new TestMultiThreadedRestoreIdentity();
      Thread t0 = new Thread(r0, "testMultiThreadedRestoreIdentity#0");
      t0.start();
      TestMultiThreadedRestoreIdentity r1 = new TestMultiThreadedRestoreIdentity();
      Thread t1 = new Thread(r1, "testMultiThreadedRestoreIdentity#1");
      t1.start();

      t0.join();
      assertTrue(r0.failure == null);
      t1.join();
      assertTrue(r1.failure == null);
   }
   static class TestMultiThreadedRestoreIdentity implements Runnable
   {
      Exception failure;
      public void run()
      {
         try
         {
            System.out.println("+++ testMultiThreadedRestoreIdentity");
      
            Principal jduke1 = new SimplePrincipal("jduke1");
            SecurityContext sc = SecurityContextAssociation.getSecurityContext();
            if (sc == null)
               sc = SecurityContextFactory.createSecurityContext("test");
            sc.getUtil().createSubjectInfo(jduke1, "theduke1", new Subject());
            SecurityContextAssociation.setSecurityContext(sc);
      
            UsernamePasswordHandler handler = new UsernamePasswordHandler("jduke2",
               "theduke2");
            LoginContext lc = new LoginContext("testMultiThreadedRestoreIdentity", handler);
            lc.login();
            Subject subject = lc.getSubject();
            System.out.println("LC.Subject: "+subject);
            
            Principal jduke2 = new SimplePrincipal("jduke2");
            assertTrue("Principals contains jduke2", subject.getPrincipals().contains(jduke2));
            Principal saPrincipal = SecurityContextAssociation.getPrincipal();
            assertTrue("SecurityContextAssociation.getPrincipal == jduke2", saPrincipal.equals(jduke2));
            char[] password = (char[]) SecurityContextAssociation.getCredential();
            assertTrue("password == theduke2",
               Arrays.equals(password, "theduke2".toCharArray()));
      
            lc.logout();
            // Validate restored state
            saPrincipal = SecurityContextAssociation.getPrincipal();
            assertTrue("SecurityContextAssociation.getPrincipal == jduke1", saPrincipal.equals(jduke1));
            String theduke1 = (String) SecurityContextAssociation.getCredential();
            assertTrue("password == theduke1", theduke1.equals("theduke1"));
      
         }
         catch(Exception e)
         {
            failure = e;
         }
      }
   }

   //SECURITY-339: ClientLoginModule abort should not clear security context
   public void testAbortWithRestore() throws Exception
   {
      SecurityContext sc = SecurityContextFactory.createSecurityContext("test");
      SecurityContextAssociation.setSecurityContext(sc);
      
      //Start with successful login. Then a failed login
      UsernamePasswordHandler handler = new UsernamePasswordHandler("jduke", "jduke");
      LoginContext lc = new LoginContext("testAbortWithRestore", handler);
      lc.login();
      Subject subject = lc.getSubject();
      assertNotNull("Subject is not null", subject);
      
      SecurityContext currentSC = SecurityContextAssociation.getSecurityContext();
      assertNotNull("Current Security Context is not null", currentSC);
      verifySubjectInfo(currentSC);
      
      //Failed Login
      handler = new UsernamePasswordHandler("jduke", "BAD_PASSWORD");
      lc = new LoginContext("testAbortWithRestore", handler);
      try
      {
         lc.login(); 
         fail("Should have failed");
      }
      catch(LoginException le)
      {
         //pass
      }
      subject = lc.getSubject();
      assertNull("Subject from login context is null", subject);
      
      currentSC = SecurityContextAssociation.getSecurityContext();
      assertNotNull("Current Security Context is not null", currentSC); 
      verifySubjectInfo(currentSC);
      
      
      //Successful Login
      SecurityContextAssociation.setSecurityContext(sc);
      handler = new UsernamePasswordHandler("jduke", "jduke");
      lc = new LoginContext("testAbortWithRestore", handler);
      lc.login();
      subject = lc.getSubject();
      assertNotNull("Subject is not null", subject);
      
      currentSC = SecurityContextAssociation.getSecurityContext();
      assertNotNull("Current Security Context is not null", currentSC);
      verifySubjectInfo(currentSC);
      
      //Failed Login
      handler = new UsernamePasswordHandler("jduke", "BAD_PASSWORD");
      lc = new LoginContext("testAbortWithRestore", handler);
      try
      {
         lc.login(); 
         fail("Should have failed");
      }
      catch(LoginException le)
      {
         //pass
      }
      subject = lc.getSubject();
      assertNull("Subject is null", subject);
      
      currentSC = SecurityContextAssociation.getSecurityContext();
      assertNotNull("Current Security Context is not null", currentSC);
      verifySubjectInfo(currentSC);
      
      lc.logout();
      subject = lc.getSubject();
      assertNull("Subject from login context is null", subject);
   }
   
   //SECURITY-339: ClientLoginModule abort should not clear security context
   public void testAbortWithNoRestore() throws Exception
   {
      SecurityContext sc = SecurityContextFactory.createSecurityContext("test");
      SecurityContextAssociation.setSecurityContext(sc);
      
      //Successful Login
      SecurityContextAssociation.setSecurityContext(sc);
      UsernamePasswordHandler handler = new UsernamePasswordHandler("jduke", "jduke");
      LoginContext lc = new LoginContext("testAbortWithNoRestore", handler);
      lc.login();
      Subject subject = lc.getSubject();
      assertNotNull("Subject is not null", subject);
      
      SecurityContext currentSC = SecurityContextAssociation.getSecurityContext();
      assertNotNull("Current Security Context is not null", currentSC);
      this.verifySubjectInfo(currentSC);
      
      //Failed Login - calls abort on the login modules
      handler = new UsernamePasswordHandler("BAD_USER", "BAD_PASSWORD");
      lc = new LoginContext("testAbortWithNoRestore", handler);
      try
      {
         lc.login(); 
         fail("Should have failed");
      }
      catch(LoginException le)
      {
         //pass
      }
      //Ensure that the failed login context does not return a subject
      subject = lc.getSubject();
      assertNull("Subject is null", subject);
      
      //We have to ensure that the security context was cleared after abort
      currentSC = SecurityContextAssociation.getSecurityContext();
      assertNull("Current Security Context is not null", currentSC);
            
      //Let us go through some logout cycles
      handler = new UsernamePasswordHandler("jduke", "jduke");
      lc = new LoginContext("testAbortWithNoRestore", handler);
      lc.login();
      subject = lc.getSubject();
      assertNotNull("Subject is not null", subject);
      
      currentSC = SecurityContextAssociation.getSecurityContext();
      assertNotNull("Current Security Context is not null", currentSC);
      this.verifySubjectInfo(currentSC);
      
      lc.logout();

      assertNull("Current Security Context is null", SecurityContextAssociation.getSecurityContext());
      subject = lc.getSubject();
      assertEquals("Subject from login context has no principals", 0, subject.getPrincipals().size());
      
      sc = SecurityContextFactory.createSecurityContext("test");
      SecurityContextAssociation.setSecurityContext(sc);
      
      //Failed Login - calls abort on the login modules
      handler = new UsernamePasswordHandler("BAD_USER", "BAD_PASSWORD");
      lc = new LoginContext("testAbortWithNoRestore", handler);
      try
      {
         lc.login(); 
         fail("Should have failed");
      }
      catch(LoginException le)
      {
         //pass
      }
      //Ensure that the failed login context does not return a subject
      subject = lc.getSubject();
      assertNull("Subject is null", subject);
      
      //We have to ensure that the security context was cleared after abort
      currentSC = SecurityContextAssociation.getSecurityContext();
      assertNull("Current Security Context is not null", currentSC);
   }
   
   private void verifySubjectInfo(SecurityContext currentSC)
   { 
      SubjectInfo subjectInfo = currentSC.getSubjectInfo();
      assertNotNull("SubjectInfo", subjectInfo);
      Subject subject = subjectInfo.getAuthenticatedSubject();
      assertNotNull("Subject is not null", subject); 
      Principal jduke = new SimplePrincipal("jduke");
      assertTrue("jduke exists in the subject",subject.getPrincipals().contains(jduke));
      assertEquals("jduke exists", jduke, currentSC.getUtil().getUserPrincipal());
      assertEquals("jduke exists", jduke, SecurityContextAssociation.getPrincipal());
   }
}