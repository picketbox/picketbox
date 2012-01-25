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
package org.jboss.test.authentication.jaspi;

import java.net.URL;
import java.util.HashMap;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.AuthConfigProvider;
import javax.security.auth.message.config.ClientAuthConfig;
import javax.security.auth.message.config.ClientAuthContext;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;

import junit.framework.TestCase;

import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.auth.callback.AppCallbackHandler;
import org.jboss.security.auth.login.XMLLoginConfigImpl;
import org.jboss.security.auth.message.GenericMessageInfo;
import org.jboss.security.plugins.JBossSecurityContext;
import org.jboss.test.SecurityActions;
import org.jboss.test.authentication.jaspi.helpers.TestAuthConfigProvider;


/**
 *  Unit Tests for the JASPI Configuration
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 11, 2007 
 *  @version $Revision$
 */
public class JASPIConfigUnitTestCase extends TestCase
{
   AuthConfigFactory factory = null;
   
   @Override
   public void setUp()
   {
      factory = AuthConfigFactory.getFactory();
      factory.registerConfigProvider(new TestAuthConfigProvider(), "TEST", "APP", 
            "Test Config Provider");
   }
   
   @SuppressWarnings("unchecked")
   public void testServerFactoryConfig() throws Exception
   { 
      assertNotNull("AuthConfigFactory is ! null", factory); 
      AuthConfigProvider provider = factory.getConfigProvider("TEST", "APP", null);
      assertNotNull("AuthConfigProvider is ! null", provider);
      
      ServerAuthConfig serverConfig =
         provider.getServerAuthConfig("TEST", "APP", 
               new AppCallbackHandler("anil","anil".toCharArray()));
      assertNotNull("ServerAuthConfig ! null", serverConfig); 
      MessageInfo mi = new GenericMessageInfo(new Object(), new Object());
      String authContextID = serverConfig.getAuthContextID(mi);
      assertNotNull("AuthContext ID != null",authContextID);
      ServerAuthContext sctx = serverConfig.getAuthContext(authContextID, 
            new Subject(), new HashMap());
      assertNotNull("ServerAuthContext != null",sctx); 
   } 
   
   @SuppressWarnings("unchecked")
   public void testClientFactoryConfig() throws Exception
   { 
      assertNotNull("AuthConfigFactory is ! null", factory); 
      AuthConfigProvider provider = factory.getConfigProvider("TEST", "APP", null);
      assertNotNull("AuthConfigProvider is ! null", provider);
      
      ClientAuthConfig clientConfig =
         provider.getClientAuthConfig("TEST", "APP", 
               new AppCallbackHandler("anil","anil".toCharArray()));
      assertNotNull("ClientAuthConfig ! null", clientConfig); 
      MessageInfo mi = new GenericMessageInfo(new Object(), new Object());
      String authContextID = clientConfig.getAuthContextID(mi);
      assertNotNull("AuthContext ID != null",authContextID);
      ClientAuthContext sctx = clientConfig.getAuthContext(authContextID, 
            new Subject(), new HashMap());
      assertNotNull("ClientAuthContext != null",sctx); 
   }
   
   public void testLoginConfigStackHolder() throws Exception
   {
      String securityDomain = "conf-jaspi";
      JBossSecurityContext jsc = new JBossSecurityContext(securityDomain);
      SecurityContextAssociation.setSecurityContext(jsc);

      String configFile = "config/jaspi-config.xml";
      loadConfig(configFile);
      
      //Lets validate the configuration
      Configuration config = Configuration.getConfiguration();
      AppConfigurationEntry[] appConfigEntries = config.getAppConfigurationEntry(securityDomain);
      assertTrue(appConfigEntries.length > 0);
      for(AppConfigurationEntry appConfigEntry: appConfigEntries)
      {
         assertEquals("org.jboss.test.authentication.jaspi.TestLoginModule",
               appConfigEntry.getLoginModuleName());
         assertEquals(LoginModuleControlFlag.OPTIONAL, appConfigEntry.getControlFlag());
      }
      
      appConfigEntries = config.getAppConfigurationEntry("lm-stack");
      assertTrue(appConfigEntries.length > 0);
      for(AppConfigurationEntry appConfigEntry: appConfigEntries)
      {
         assertEquals("org.jboss.test.authentication.jaspi.TestLoginModule",
               appConfigEntry.getLoginModuleName());
         assertEquals(LoginModuleControlFlag.OPTIONAL, appConfigEntry.getControlFlag());
      }
   }
   
   private void loadConfig(String configFile)
   {
      XMLLoginConfigImpl xli = XMLLoginConfigImpl.getInstance();
      SecurityActions.setJAASConfiguration(xli);

      URL configURL = Thread.currentThread().getContextClassLoader().getResource(configFile);
      assertNotNull("Config URL", configURL);

      xli.setConfigURL(configURL);
      xli.loadConfig();
   }
    
}
