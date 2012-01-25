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
package org.jboss.test.authentication;

import java.security.Principal;
import java.util.HashMap;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;

import junit.framework.TestCase;

import org.jboss.security.AuthenticationManager;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.callback.AppCallbackHandler;
import org.jboss.security.plugins.JBossAuthenticationManager;
import org.jboss.test.SecurityActions;

//$Id$

/**
 *  Unit tests for the JBossAuthenticationManager
 *  @author Anil.Saldhana@redhat.com
 *  @since  May 10, 2007 
 *  @version $Revision$
 */
public class JBossAuthenticationManagerUnitTestCase extends TestCase
{ 
   @Override
   protected void setUp() throws Exception
   {
      super.setUp();
      establishSecurityConfiguration();
   }

   public void testSecurityDomain() throws Exception
   {
      AuthenticationManager am = new JBossAuthenticationManager("test1", 
            new AppCallbackHandler("a","b".toCharArray()));
      assertEquals("test1", am.getSecurityDomain());
   }
   
   public void testLogin() throws Exception
   {
      Principal p = new SimplePrincipal("jduke");
      AppCallbackHandler acbh = new AppCallbackHandler("jduke","theduke".toCharArray());
      AuthenticationManager am = new JBossAuthenticationManager("test",acbh);
      assertTrue(am.isValid(p, "theduke")); 
   }  
   
   public void testUnsuccessfulLogin() throws Exception
   {
      Principal p = new SimplePrincipal("jduke");
      AppCallbackHandler acbh = new AppCallbackHandler("jduke","bad".toCharArray());
      AuthenticationManager am = new JBossAuthenticationManager("test",acbh);
      assertFalse(am.isValid(p, "bad")); 
   }
   
   private void establishSecurityConfiguration()
   { 
      SecurityActions.setJAASConfiguration((Configuration)new TestConfig());
   }
   
   public class TestConfig extends Configuration
   { 
      @Override
      public AppConfigurationEntry[] getAppConfigurationEntry(String name)
      {
         HashMap<String,Object> map = new HashMap<String,Object>();
         map.put("usersProperties", "users.properties"); 
         map.put("rolesProperties", "roles.properties");
         String moduleName = "org.jboss.security.auth.spi.UsersRolesLoginModule";
         AppConfigurationEntry ace = new AppConfigurationEntry(moduleName,
               LoginModuleControlFlag.REQUIRED, map);
         
         return new AppConfigurationEntry[]{ace};
      }

      @Override
      public void refresh()
      {
      } 
   }
}
