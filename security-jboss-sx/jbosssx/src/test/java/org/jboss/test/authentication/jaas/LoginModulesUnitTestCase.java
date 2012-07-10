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
package org.jboss.test.authentication.jaas;

import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.Principal;
import java.security.acl.Group;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import junit.framework.TestCase;

import org.jboss.crypto.CryptoUtil;
import org.jboss.logging.Logger;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.callback.UsernamePasswordHandler;
import org.jboss.security.auth.spi.UsernamePasswordLoginModule;

/** Tests of the LoginModule classes.
 * 
 * ANIL: Not all the login modules are tested here. There is a larger
 * test case in AS trunk that tests most of the LMs 
 * @author Scott.Stark@jboss.org
 * @version $Revision$
 */
@SuppressWarnings("unchecked")
public class LoginModulesUnitTestCase extends TestCase
{

  private static Logger log = Logger.getLogger(LoginModulesUnitTestCase.class);

  /** Hard coded login configurations for the test cases. The configuration
   name corresponds to the unit test function that uses the configuration.
   */
  static class TestConfig extends Configuration
  {
     @Override
   public void refresh()
     {
     }

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
        catch(Exception e)
        {
        }
        return entry;
     }

     AppConfigurationEntry[] testClientLogin()
     {
        String name = "org.jboss.security.ClientLoginModule";
        HashMap options = new HashMap();
        options.put("restore-login-identity", "true");
        AppConfigurationEntry ace = new AppConfigurationEntry(name,
        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
        AppConfigurationEntry[] entry = {ace};
        return entry;
     }
     
     AppConfigurationEntry[] testIdentity()
     {
        String name = "org.jboss.security.auth.spi.IdentityLoginModule";
        HashMap options = new HashMap();
        options.put("principal", "stark");
        options.put("roles", "Role3,Role4");
        AppConfigurationEntry ace = new AppConfigurationEntry(name,
        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
        AppConfigurationEntry[] entry = {ace};
        return entry;
     } 
     
     AppConfigurationEntry[] testSimple()
     {
        String name = "org.jboss.security.auth.spi.SimpleServerLoginModule";
        AppConfigurationEntry ace = new AppConfigurationEntry(name,
        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, new HashMap());
        AppConfigurationEntry[] entry = {ace};
        return entry;
     }
     AppConfigurationEntry[] testUsernamePassword()
     {
        return other();
     } 
     AppConfigurationEntry[] testAnon()
     {
        String name = "org.jboss.security.auth.spi.AnonLoginModule";
        HashMap options = new HashMap();
        options.put("unauthenticatedIdentity", "nobody");
        AppConfigurationEntry ace = new AppConfigurationEntry(name,
           AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
        AppConfigurationEntry[] entry = {ace};
        return entry;
     }
     AppConfigurationEntry[] testNull()
     {
        String name = "org.jboss.security.auth.spi.AnonLoginModule";
        HashMap options = new HashMap();
        AppConfigurationEntry ace = new AppConfigurationEntry(name,
        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
        AppConfigurationEntry[] entry = {ace};
        return entry;
     }
     AppConfigurationEntry[] testUsersRoles()
     {
        String name = "org.jboss.security.auth.spi.UsersRolesLoginModule";
        HashMap options = new HashMap();
        options.put("usersProperties", "security/users.properties");
        options.put("rolesProperties", "security/roles.properties");
        AppConfigurationEntry ace = new AppConfigurationEntry(name,
        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
        AppConfigurationEntry[] entry = {ace};
        return entry;
     }  
     
     AppConfigurationEntry[] testSharedMap()
     {
        String name = "org.jboss.test.authentication.jaas.helpers.SharedStatePopulatingLoginModule";
        HashMap options = new HashMap(); 
        options.put("useFirstPass", "true");  
     
        String anothername = 
           "org.jboss.test.authentication.jaas.helpers.SharedStateRetrievingLoginModule";
        
        HashMap anotherOptions = new HashMap();
        anotherOptions.put("username", "anil");
        anotherOptions.put("password", "superman");
        
        AppConfigurationEntry ace = new AppConfigurationEntry(name,
        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
        
        AppConfigurationEntry anotherAce = new AppConfigurationEntry(anothername,
              AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, anotherOptions);
        AppConfigurationEntry[] entry = {ace,anotherAce};
        return entry;
     }

     /**
       * <p>
       * Obtains a configuration that uses a module that fails the validation phase. As the flag
       * {@code throwValidateError} is not set to true, the validation exception should be available to the test method.
       * </p>
       * 
       * @return the test {@code AppConfigurationEntry}.
       */
      AppConfigurationEntry[] testValidateError()
      {
         AppConfigurationEntry entry = new AppConfigurationEntry(ValidateErrorLoginModule.class.getName(),
               AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, new HashMap());
         return new AppConfigurationEntry[]
         {entry};
      }

      /**
       * <p>
       * Obtains a configuration that uses a module that fails the validation phase. As the flag
       * {@code throwValidateError} is set to true, the validation exception should available to the test method.
       * </p>
       * 
       * @return the test {@code AppConfigurationEntry}.
       */
     AppConfigurationEntry[] testValidateErrorWithFlag()
     {
        HashMap options = new HashMap();
        options.put("throwValidateError", "true");
        AppConfigurationEntry entry = new AppConfigurationEntry(ValidateErrorLoginModule.class.getName(),
              AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
        return new AppConfigurationEntry[]{entry};
     }
     
     /**
      * <p>
      * Obtains a configuration that uses a module in conjunction with an {@code InputValidator} to check if the
      * supplied username and password are valid.
      * </p>
      * 
      * @return the test {@code AppConfigurationEntry}.
      */
     AppConfigurationEntry[] testInputValidator()
     {
        HashMap options = new HashMap();
        options.put("inputValidator", "org.jboss.test.authentication.jaas.helpers.TestInputValidator");
        AppConfigurationEntry entry = new AppConfigurationEntry(TestLoginModule.class.getName(),
              AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
        return new AppConfigurationEntry[]{entry};
     }
     
     AppConfigurationEntry[] other()
     {
        AppConfigurationEntry ace = new AppConfigurationEntry(TestLoginModule.class.getName(),
        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, new HashMap());
        AppConfigurationEntry[] entry = {ace};
        return entry;
     }
  }

  public static class TestLoginModule extends UsernamePasswordLoginModule
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
  
  public static class HashTestLoginModule extends TestLoginModule
  {
     /** This represents the 'true' password in its hashed form
      */
     @Override
   protected String getUsersPassword()
     {
        MessageDigest md = null;
        try
        {
           md = MessageDigest.getInstance("MD5");
        }
        catch(Exception e)
        {
           e.printStackTrace();
        }
        byte[] passwordBytes = "secret".getBytes();
        byte[] hash = md.digest(passwordBytes);
        String passwordHash = CryptoUtil.encodeBase64(hash);
        return passwordHash;
     }
  }
  public static class HashTestDigestCallbackLoginModule extends TestLoginModule
  {
     /** This represents the 'true' password in its hashed form
      */
     @Override
   protected String getUsersPassword()
     {
        MessageDigest md = null;
        try
        {
           md = MessageDigest.getInstance("MD5");
        }
        catch(Exception e)
        {
           e.printStackTrace();
        }
        byte[] passwordBytes = "secret".getBytes();
        md.update("pre".getBytes());
        md.update(passwordBytes);
        md.update("post".getBytes());
        byte[] hash = md.digest();
        String passwordHash = CryptoUtil.encodeBase64(hash);
        return passwordHash;
     }
  } 

  /**
   * <p>
   * Login module used in the throwValidateError tests.
   * </p>
   */
  public static class ValidateErrorLoginModule extends TestLoginModule
   {

      @Override
      protected boolean validatePassword(String inputPassword, String expectedPassword)
      {
         // sets a validate error and returns false.
         super.setValidateError(new Exception("Validate Exception"));
         return false;
      }
   }
  
  public LoginModulesUnitTestCase(String testName)
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

  public void testClientLogin() throws Exception
  {
     log.info("testClientLogin");
     UsernamePasswordHandler handler = new UsernamePasswordHandler("scott", "secret".toCharArray());
     LoginContext lc = new LoginContext("testClientLogin", handler);
     lc.login();
     Subject subject = lc.getSubject();
     Principal scott = new SimplePrincipal("scott");
     assertTrue("Principals contains scott", subject.getPrincipals().contains(scott));
     Principal saPrincipal = SecurityContextAssociation.getPrincipal();
     assertTrue("SecurityAssociation.getPrincipal == scott", saPrincipal.equals(scott));

     UsernamePasswordHandler handler2 = new UsernamePasswordHandler("scott2", "secret2".toCharArray());
     LoginContext lc2 = new LoginContext("testClientLogin", handler2);
     lc2.login();
     Principal scott2 = new SimplePrincipal("scott2");
     saPrincipal = SecurityContextAssociation.getPrincipal();
     assertTrue("SecurityAssociation.getPrincipal == scott2", saPrincipal.equals(scott2));
     lc2.logout();
     saPrincipal = SecurityContextAssociation.getPrincipal();
     assertTrue("SecurityAssociation.getPrincipal == scott", saPrincipal.equals(scott));
     
     lc.logout();      
  }

  public void testUsernamePassword() throws Exception
  {
     log.info("testUsernamePassword");
     UsernamePasswordHandler handler = new UsernamePasswordHandler("scott", "secret".toCharArray());
     LoginContext lc = new LoginContext("testUsernamePassword", handler);
     lc.login();
     Subject subject = lc.getSubject();
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

     lc.logout();
  }
  public void testUsernamePasswordHash() throws Exception
  {
     log.info("testUsernamePasswordHash");
     UsernamePasswordHandler handler = new UsernamePasswordHandler("scott", "secret".toCharArray());
     LoginContext lc = new LoginContext("testUsernamePasswordHash", handler);
     lc.login();
     Subject subject = lc.getSubject();
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

     lc.logout();
  }
 
  public void testAnon() throws Exception
  {
     log.info("testAnon");
     UsernamePasswordHandler handler = new UsernamePasswordHandler(null, null);
     LoginContext lc = new LoginContext("testAnon", handler);
     lc.login();
     Subject subject = lc.getSubject();
     Set<Group> groups = subject.getPrincipals(Group.class);
     Principal nobody = new SimplePrincipal("nobody");
     assertTrue("Principals contains nobody", subject.getPrincipals().contains(nobody));
     assertTrue("Principals contains Roles", groups.contains(new SimpleGroup("Roles")));
     assertTrue("Principals contains CallerPrincipal", groups.contains(new SimpleGroup("CallerPrincipal")));
     for (Group group : groups)
     {
        if (group.getName().equals("Roles"))
        {
           assertTrue("Roles has no members", !group.members().hasMoreElements());
        }
        else if (group.getName().equals("CallerPrincipal"))
        {
           Enumeration<? extends Principal> roles = group.members();
           assertEquals("CallerPrincipal group has 1 entry", 1, Collections.list(roles).size());
           assertTrue("scott is the caller principal", group.isMember(nobody));
        }
        else
        {
           fail("Another group was set: " + group.getName());
        }
     }

     lc.logout();
  }
  public void testNull() throws Exception
  {
     log.info("testNull");
     UsernamePasswordHandler handler = new UsernamePasswordHandler(null, null);
     LoginContext lc = new LoginContext("testNull", handler);
     try
     {
        lc.login();
        fail("Should not be able to login as null, null");
     }
     catch(LoginException e)
     {
        // Ok
     }
  }

  public void testIdentity() throws Exception
  {
     log.info("testIdentity");
     LoginContext lc = new LoginContext("testIdentity");
     lc.login();
     Subject subject = lc.getSubject();
     Set<Group> groups = subject.getPrincipals(Group.class);
     Principal stark = new SimplePrincipal("stark");
     assertTrue("Principals contains stark", subject.getPrincipals().contains(stark));
     assertTrue("Principals contains Roles", groups.contains(new SimpleGroup("Roles")));
     assertTrue("Principals contains CallerPrincipal", groups.contains(new SimpleGroup("CallerPrincipal")));
     for (Group group : groups)
     {
        if (group.getName().equals("Roles"))
        {
           Enumeration<? extends Principal> roles = group.members();
           assertEquals("Roles group has 2 entries", 2, Collections.list(roles).size());
           assertTrue("Role2 is not a role", !group.isMember(new SimplePrincipal("Role2")));
           assertTrue("Role3 is a role", group.isMember(new SimplePrincipal("Role3")));
           assertTrue("Role4 is a role", group.isMember(new SimplePrincipal("Role4")));
        }
        else if (group.getName().equals("CallerPrincipal"))
        {
           Enumeration<? extends Principal> roles = group.members();
           assertEquals("CallerPrincipal group has 1 entry", 1, Collections.list(roles).size());
           assertTrue("scott is the caller principal", group.isMember(stark));
        }
        else
        {
           fail("Another group was set: " + group.getName());
        }
     }

     lc.logout();
  } 
  public void testSimple() throws Exception
  {
     log.info("testSimple");
     UsernamePasswordHandler handler = new UsernamePasswordHandler("jduke", "jduke".toCharArray());
     LoginContext lc = new LoginContext("testSimple", handler);
     lc.login();
     Subject subject = lc.getSubject();
     Set<Group> groups = subject.getPrincipals(Group.class);
     Principal jduke = new SimplePrincipal("jduke");
     assertTrue("Principals contains jduke", subject.getPrincipals().contains(jduke));
     assertTrue("Principals contains Roles", groups.contains(new SimpleGroup("Roles")));
     assertTrue("Principals contains CallerPrincipal", groups.contains(new SimpleGroup("CallerPrincipal")));
     for (Group group : groups)
     {
        if (group.getName().equals("Roles"))
        {
           Enumeration<? extends Principal> roles = group.members();
           assertEquals("Roles group has 2 entries", 2, Collections.list(roles).size());
           assertTrue("user is a role", group.isMember(new SimplePrincipal("user")));
           assertTrue("guest is a role", group.isMember(new SimplePrincipal("guest")));
        }
        else if (group.getName().equals("CallerPrincipal"))
        {
           Enumeration<? extends Principal> roles = group.members();
           assertEquals("CallerPrincipal group has 1 entry", 1, Collections.list(roles).size());
           assertTrue("scott is the caller principal", group.isMember(jduke));
        }
        else
        {
           fail("Another group was set: " + group.getName());
        }
     }

     lc.logout();
  }
  

  public void testSharedMap() throws Exception
  {
     log.info("testSharedMap");
     UsernamePasswordHandler handler = new UsernamePasswordHandler("anil", "superman".toCharArray());
     LoginContext lc = new LoginContext("testSharedMap", handler);
     lc.login();
     Subject subject = lc.getSubject();
     assertTrue("Principals contains jduke", subject.getPrincipals().contains(new SimplePrincipal("anil")));
     lc.logout();
  }

  /**
   * <p>
   * Tests the behavior of the {@code throwValidateError flag}. The test uses a login module that fails the validation
   * phase and sets a validation exception with an error message. In the first scenario, a configuration that doesn't
   * set the {@code throwValidateError} flag is used. As a result, the exception that is caught should not have any
   * cause set. In the second scenario, a configuration that sets the flag to {@code true} is used. As a result, the
   * exception that is caught should contain the validation exception as the root cause.
   * </p>
   * 
   * @throws Exception if an error occurs while running the test.
   */
  public void testValidateError() throws Exception
  {
     // test the configuration that doesn't set the throwValidateError flag.
     LoginContext context = new LoginContext("testValidateError", new UsernamePasswordHandler(null, null));
     try 
     {
        context.login();
        fail("Login should have failed as the validation of the test module was unsuccessful");
     } 
     catch(LoginException le)
     {
        assertNull("Unexpected root throwable found", le.getCause());
     }
     
     // test the configuration that sets the throwValidateError flag.
     context = new LoginContext("testValidateErrorWithFlag", new UsernamePasswordHandler(null, null));
     try 
     {
        context.login();
        fail("Login should have failed as THE validation of the test module was unsuccessful");
     } 
     catch(LoginException le)
     {
        assertNotNull("Unexpected null root throwable", le.getCause());
        assertEquals("Invalid root message", "Validate Exception", le.getCause().getMessage());
     }
     
  }
  
  /**
   * <p>
   * Tests the usage of an {@code InputValidator} to verify that the client-supplied username and password
   * adhere to the expected rules.
   * </p>
   * 
   * @throws Exception if an error occurs while running the test.
   */
  public void testInputValidator() throws Exception
  {
     // let's start with a valid username/password pair.
     LoginContext context = new LoginContext("testInputValidator", new UsernamePasswordHandler("user", "secret"));
     context.login();
     assertNotNull(context.getSubject());
     context.logout();
     
     // now let's try a username that doesn't conform to the [A-Za-z0-9]* pattern.
     context = new LoginContext("testInputValidator", new UsernamePasswordHandler("$user$", "secret"));
     try
     {
        context.login();
        fail("Login should have failed as the supplied username does not adhere to the expected pattern");
     }
     catch(LoginException le)
     {
        assertEquals("Username or password does not adhere to the acceptable pattern", le.getMessage());
     }
     
     // now let's try a password that doesn't conform to the pattern by including a space in the middle of the password).
     context = new LoginContext("testInputValidator", new UsernamePasswordHandler("user", "sec ret"));
     try
     {
        context.login();
        fail("Login should have failed as the supplied username does not adhere to the expected pattern");
     }
     catch(LoginException le)
     {
        assertEquals("Username or password does not adhere to the acceptable pattern", le.getMessage());
     }
     
     // finally, let's try a username that has one of the blacklisted tokens.
     context = new LoginContext("testInputValidator", new UsernamePasswordHandler("javaINSERTduke", "secret"));
     try
     {
        context.login();
        fail("Login should have failed as the supplied username does not adhere to the expected pattern");
     }
     catch(LoginException le)
     {
        assertEquals("Username or password contains invalid tokens", le.getMessage());
     }

  }
}