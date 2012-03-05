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
package org.jboss.security.auth.login;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;

import javax.security.auth.AuthPermission;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;

import org.jboss.logging.Logger;
import org.jboss.security.ErrorCodes;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.ApplicationPolicyRegistration;
import org.jboss.security.config.PolicyConfig;
import org.jboss.security.config.SecurityConfiguration;
import org.jboss.security.config.parser.StaxBasedConfigParser;

/**
 * An concrete implementation of the javax.security.auth.login.Configuration class that parses an xml configuration of
 * the form:
 * 
 * <policy> <application-policy name = "test-domain"> <authentication> <login-module code =
 * "org.jboss.security.plugins.samples.IdentityLoginModule" flag = "required"> <module-option name = "principal">starksm</module-option>
 * </login-module> </authentication> </application-policy> </policy>
 * 
 * @see javax.security.auth.login.Configuration
 * 
 * @author Scott.Stark@jboss.org
 * @author Anil.Saldhana@jboss.org
 * @version $Revision: 57482 $
 */
@SuppressWarnings({"rawtypes","unchecked"})
public class XMLLoginConfigImpl extends Configuration implements Serializable, ApplicationPolicyRegistration
{
   /** The serialVersionUID */
   private static final long serialVersionUID = -8965860493224188277L;

   private static final String DEFAULT_APP_CONFIG_NAME = "other";

   private static final AuthPermission REFRESH_PERM = new AuthPermission("refreshLoginConfiguration");

   private static Logger log = Logger.getLogger(XMLLoginConfigImpl.class);
   private boolean trace = log.isTraceEnabled();

   transient PolicyConfig appConfigs = new PolicyConfig();

   /** The URL to the XML or Sun login configuration */
   protected URL loginConfigURL;

   /** The inherited configuration we delegate to */
   protected Configuration parentConfig;

   /** A flag indicating if XML configs should be validated */
   private boolean validateDTD = true;

   private static final XMLLoginConfigImpl instance = new XMLLoginConfigImpl();

   /**
    * <p>
    * Private constructor to implement the singleton pattern.
    * </p>
    */
   private XMLLoginConfigImpl()
   {
   }

   /**
    * <p>
    * Obtains a reference to the singleton.
    * </p>
    * 
    * @return a reference to the singleton {@code XMLLoginConfigImpl} instance.
    */
   public static XMLLoginConfigImpl getInstance()
   {
      return instance;
   }

   // --- Begin Configuration method overrrides
   @Override
   public void refresh()
   {
      SecurityManager sm = System.getSecurityManager();
      if (sm != null)
         sm.checkPermission(REFRESH_PERM);
      if (log.isTraceEnabled())
         log.trace("Begin refresh");
      appConfigs.clear();
      loadConfig();
      if (log.isTraceEnabled())
         log.trace("End refresh");
   }

   @Override
   public AppConfigurationEntry[] getAppConfigurationEntry(String appName)
   {
      if (log.isTraceEnabled())
         log.trace("Begin getAppConfigurationEntry(" + appName + "), size=" + appConfigs.size());

      // Load the config if PolicyConfig is empty
      if (this.appConfigs.size() == 0)
         this.loadConfig();

      AppConfigurationEntry[] entry = null;
      ApplicationPolicy aPolicy = this.getApplicationPolicy(appName);
      BaseAuthenticationInfo authInfo = null;
      if (aPolicy != null)
         authInfo = aPolicy.getAuthenticationInfo();

      if (authInfo == null)
      {
         if (log.isTraceEnabled())
            log.trace("getAppConfigurationEntry(" + appName + "), no entry in appConfigs, tyring parentCont: "
                  + parentConfig);
         if (parentConfig != null)
            entry = parentConfig.getAppConfigurationEntry(appName);
         if (entry == null)
         {
            if (log.isTraceEnabled())
               log.trace("getAppConfigurationEntry(" + appName + "), no entry in parentConfig, trying: "
                     + DEFAULT_APP_CONFIG_NAME);
         }
         ApplicationPolicy defPolicy = appConfigs.get(DEFAULT_APP_CONFIG_NAME);
         authInfo = defPolicy != null ? (AuthenticationInfo) defPolicy.getAuthenticationInfo() : null;
      }

      if (authInfo != null)
      {
         if (log.isTraceEnabled())
            log.trace("End getAppConfigurationEntry(" + appName + "), authInfo=" + authInfo);
         // Make a copy of the authInfo object
         final BaseAuthenticationInfo theAuthInfo = authInfo;
         PrivilegedAction<AppConfigurationEntry[]> action = new PrivilegedAction<AppConfigurationEntry[]>()
         {
            public AppConfigurationEntry[] run()
            {
               return theAuthInfo.copyAppConfigurationEntry();
            }
         };
         entry = AccessController.doPrivileged(action);
      }
      else
      {
         if (log.isTraceEnabled())
            log.trace("End getAppConfigurationEntry(" + appName + "), failed to find entry");
      }

      return entry;
   }

   // --- End Configuration method overrrides

   /**
    * Set the URL of the XML login configuration file that should be loaded by this mbean on startup.
    */
   public URL getConfigURL()
   {
      return loginConfigURL;
   }

   /**
    * Set the URL of the XML login configuration file that should be loaded by this mbean on startup.
    */
   public void setConfigURL(URL loginConfigURL)
   {
      this.loginConfigURL = loginConfigURL;
   }

   public void setConfigResource(String resourceName) throws IOException
   {
      ClassLoader tcl = SecurityActions.getContextClassLoader();
      loginConfigURL = tcl.getResource(resourceName);
      if (loginConfigURL == null)
         throw new IOException(ErrorCodes.NULL_VALUE + "Failed to find resource: " + resourceName);
   }

   public void setParentConfig(Configuration parentConfig)
   {
      this.parentConfig = parentConfig;
   }

   /**
    * Get whether the login config xml document is validated againsts its DTD
    */
   public boolean getValidateDTD()
   {
      return this.validateDTD;
   }

   /**
    * Set whether the login config xml document is validated againsts its DTD
    */
   public void setValidateDTD(boolean flag)
   {
      this.validateDTD = flag;
   }

   /**
    * @see ApplicationPolicyRegistration#addApplicationPolicy(String, ApplicationPolicy)
    */
   public void addApplicationPolicy(String appName, ApplicationPolicy aPolicy)
   {
      SecurityManager sm = System.getSecurityManager();
      if (sm != null)
         sm.checkPermission(REFRESH_PERM);
      appConfigs.add(aPolicy);
      handleJASPIDelegation(aPolicy);
      SecurityConfiguration.addApplicationPolicy(aPolicy);
   }

   /**
    * Add an application configuration
    */
   public void addAppConfig(String appName, AppConfigurationEntry[] entries)
   {
      SecurityManager sm = System.getSecurityManager();
      if (sm != null)
         sm.checkPermission(REFRESH_PERM);
      AuthenticationInfo authInfo = new AuthenticationInfo(appName);
      authInfo.setAppConfigurationEntry(entries);
      if (log.isTraceEnabled())
         log.trace("addAppConfig(" + appName + "), authInfo=" + authInfo);
      ApplicationPolicy aPolicy = new ApplicationPolicy(appName, authInfo);
      appConfigs.add(aPolicy);
      SecurityConfiguration.addApplicationPolicy(aPolicy);
   }
   
   public void copy(PolicyConfig policyConfig)
   {
      this.appConfigs.copy(policyConfig);
   }

   /**
    * @deprecated
    * @see #removeApplicationPolicy(String)
    * @param appName
    */
   @Deprecated
   public void removeAppConfig(String appName)
   {
      SecurityManager sm = System.getSecurityManager();
      if (sm != null)
         sm.checkPermission(REFRESH_PERM);
      if (log.isTraceEnabled())
         log.trace("removeAppConfig, appName=" + appName);
      appConfigs.remove(appName);
      SecurityConfiguration.removeApplicationPolicy(appName);
   }

   /**
    * @see ApplicationPolicyRegistration#getApplicationPolicy(String)
    */
   public ApplicationPolicy getApplicationPolicy(String domainName)
   {
      if (appConfigs == null || appConfigs.size() == 0)
         loadConfig();
      ApplicationPolicy aPolicy = null;
      if(appConfigs != null )
         aPolicy = appConfigs.get(domainName);
      if (aPolicy != null)
         SecurityConfiguration.addApplicationPolicy(aPolicy);
      return aPolicy;
   }

   /**
    * @see ApplicationPolicyRegistration#removeApplicationPolicy(String)
    */
   public boolean removeApplicationPolicy(String appName)
   {
      SecurityManager sm = System.getSecurityManager();
      if (sm != null)
         sm.checkPermission(REFRESH_PERM);
      if (log.isTraceEnabled())
         log.trace("removeAppConfig, appName=" + appName);
      appConfigs.remove(appName);
      SecurityConfiguration.removeApplicationPolicy(appName);
      return true;
   }

   /**
    * Method that returns the parsed AuthenticationInfo needed by the JASPI framework until a seperate Configuration
    * mechanism for JASPI is established
    * 
    * @return the parsed AuthenticationInfo object
    */
   public BaseAuthenticationInfo getAuthenticationInfo(String domainName)
   {
      ApplicationPolicy aPolicy = getApplicationPolicy(domainName);
      return aPolicy != null ? aPolicy.getAuthenticationInfo() : null;
   }

   public void clear()
   {

   }

   /**
    * Called to try to load the config from the java.security.auth.login.config property value when there is no
    * loginConfigURL.
    */
   @SuppressWarnings("deprecation")
   public void loadConfig()
   {
      // Try to load the java.security.auth.login.config property
      String loginConfig = System.getProperty("java.security.auth.login.config");
      if (loginConfig == null)
         loginConfig = "login-config.xml";

      // If there is no loginConfigURL build it from the loginConfig
      if (loginConfigURL == null)
      {
         try
         {
            // Try as a URL
            loginConfigURL = new URL(loginConfig);
         }
         catch (MalformedURLException e)
         {
            // Try as a resource
            try
            {
               setConfigResource(loginConfig);
            }
            catch (IOException ignore)
            {
               // Try as a file
               File configFile = new File(loginConfig);
               try
               {
                  setConfigURL(configFile.toURL());
               }
               catch (MalformedURLException ignore2)
               {
               }
            }
         }
      }

      if (loginConfigURL == null)
      {
         log.warn("Failed to find config: " + loginConfig);
         return;
      }

      if (log.isTraceEnabled())
         log.trace("Begin loadConfig, loginConfigURL=" + loginConfigURL);
      // Try to load the config if found
      try
      {
         loadConfig(loginConfigURL);
         if (log.isTraceEnabled())
            log.trace("End loadConfig, loginConfigURL=" + loginConfigURL);
      }
      catch (Exception e)
      {
         log.warn("End loadConfig, failed to load config: " + loginConfigURL, e);
      }
   }
 
   protected String[] loadConfig(URL config) throws Exception
   {
      SecurityManager sm = System.getSecurityManager();
      if (sm != null)
         sm.checkPermission(REFRESH_PERM);

      ArrayList configNames = new ArrayList();
      log.debug("Try loading config as XML, url=" + config);
      try
      {
         loadXMLConfig(config, configNames);
      }
      catch (Throwable e)
      {
         if(trace)
         {
            log.debug("Failed to load config as XML", e);
            log.debug("Try loading config as Sun format, url=" + config);
         }
         loadSunConfig(config, configNames);
      }
      String[] names = new String[configNames.size()];
      configNames.toArray(names);
      return names;
   }

   /**
    * Handle the case when JASPI Info may have login module stack holder which delegates to a login module stack
    * 
    * @param aPolicy
    */
   private void handleJASPIDelegation(ApplicationPolicy aPolicy)
   {
      BaseAuthenticationInfo bai = aPolicy.getAuthenticationInfo();
      if (bai instanceof JASPIAuthenticationInfo)
      {
         JASPIAuthenticationInfo jai = (JASPIAuthenticationInfo) bai;
         LoginModuleStackHolder[] lmsharr = jai.getLoginModuleStackHolder();
         for (LoginModuleStackHolder lmsh : lmsharr)
         {
            this.addAppConfig(lmsh.getName(), lmsh.getAppConfigurationEntry());
         }
      }
   }
 
   private void loadSunConfig(URL sunConfig, ArrayList configNames) throws Exception
   {
      InputStream is = null;
      InputStreamReader configFile = null;
      try
      {
         is = sunConfig.openStream();
         if (is == null)
            throw new IOException(ErrorCodes.NULL_VALUE + "InputStream is null for: " + sunConfig);

         configFile = new InputStreamReader(is);
         boolean trace = log.isTraceEnabled();
         SunConfigParser.doParse(configFile, this, trace);
      }
      finally
      {
         safeClose(configFile);
         safeClose(is);
      }
   }
 
   private void loadXMLConfig(URL loginConfigURL, ArrayList configNames) throws Exception
   {
      InputStream is = null;
      try
      {
         is = loginConfigURL.openStream();

         StaxBasedConfigParser parser = new StaxBasedConfigParser();
         parser.parse(is);
      }
      finally
      {
         safeClose(is);
      }
   }
   
   private void safeClose(InputStream fis)
   {
      try
      {
         if(fis != null)
         {
            fis.close();
         }
      }
      catch(Exception e)
      {}
   }
   private void safeClose(InputStreamReader fis)
   {
      try
      {
         if(fis != null)
         {
            fis.close();
         }
      }
      catch(Exception e)
      {}
   }
}