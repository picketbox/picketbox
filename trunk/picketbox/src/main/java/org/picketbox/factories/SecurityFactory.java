/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2006, Red Hat Middleware LLC, and individual contributors
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
package org.picketbox.factories;

import java.net.URL;

import javax.security.auth.login.Configuration;

import org.jboss.security.AuthenticationManager;
import org.jboss.security.AuthorizationManager;
import org.jboss.security.ErrorCodes;
import org.jboss.security.ISecurityManagement;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextFactory;
import org.jboss.security.audit.AuditManager;
import org.jboss.security.config.ApplicationPolicyRegistration;
import org.jboss.security.config.StandaloneConfiguration;
import org.jboss.security.mapping.MappingManager;
import org.picketbox.plugins.PicketBoxSecurityManagement;

/**
 * Security Factory
 * This is the main factory for PicketBox
 * 
 * Two methods that are important are {@link #prepare()} and {@link #release()}
 * <a href="mailto:anil.saldhana@redhat.com">Anil Saldhana</a>
 */
public class SecurityFactory
{
   private static ISecurityManagement securityManagement = new PicketBoxSecurityManagement();
   
   private static Configuration parentConfiguration = null;
   
   static
   { 
      try
      {
         ClassLoader tcl = SecurityActions.getContextClassLoader();
         if( tcl == null )
            throw new IllegalStateException( ErrorCodes.NULL_VALUE + "TCCL has not been set" );
         URL configLocation = tcl.getResource("auth.conf");
         String prop = "java.security.auth.login.config";
         if(SecurityActions.getSystemProperty(prop, null) == null)
         {
            if( configLocation == null )
               throw new RuntimeException( ErrorCodes.NULL_VALUE + 
            		   "Neither system property *java.security.auth.login.config* available or auth.conf present" );

            SecurityActions.setSystemProperty(prop, configLocation.toExternalForm());  
         }
         
         parentConfiguration = Configuration.getConfiguration();
      }
      catch(Exception e)
      {
         throw new RuntimeException(ErrorCodes.PROCESSING_FAILED + "Unable to init SecurityFactory:", e);
      }
   }
   
   private static StandaloneConfiguration standaloneConfiguration = StandaloneConfiguration.getInstance();
   
   /**
    * Get the {@code AuthenticationManager} interface
    * @param securityDomain security domain such as "other"
    * @return
    */
   public static AuthenticationManager getAuthenticationManager(String securityDomain)
   {
      validate();
      return securityManagement.getAuthenticationManager(securityDomain);
   }
   
   /**
    * Get the {@code AuthorizationManager} interface
    * @param securityDomain security domain such as "other"
    * @return
    */
   public static AuthorizationManager getAuthorizationManager(String securityDomain)
   {
      validate();
      return securityManagement.getAuthorizationManager(securityDomain);
   }
   
   /**
    * Get the {@code AuditManager} interface
    * @param securityDomain security domain such as "other"
    * @return
    */
   public static AuditManager getAuditManager(String securityDomain)
   {
      validate();
      return securityManagement.getAuditManager(securityDomain);
   }
   
   /**
    * Get the {@code MappingManager}
    * @param securityDomain
    * @return
    */
   public static MappingManager getMappingManager(String securityDomain)
   {
      validate();
      return securityManagement.getMappingManager(securityDomain);
   }
   
   /**
    * Get the {@code ISecurityManagement} interface  
    * @return
    */
   public static ISecurityManagement getSecurityManagement()
   {
      return securityManagement;
   }
   
   /**
    * Set {@code ISecurityManagement}
    * @param iSecurityManagement
    */
   public static void setSecurityManagement(ISecurityManagement iSecurityManagement)
   {
      securityManagement = iSecurityManagement;
   }
 
   /**
    * Prepare for security operations. One of the operations
    * that is undertaken is to establish the JAAS {@code Configuration}
    * that uses our xml based configuration.
    * @see #release() to release the configuration
    */
   public static void prepare()
   { 
      if(Configuration.getConfiguration() instanceof ApplicationPolicyRegistration == false)
      {
         standaloneConfiguration.setParentConfig(parentConfiguration);
         Configuration.setConfiguration(standaloneConfiguration);
      }
      setLog4JLogger();
   }
   
   /**
    * Establish a security context on the thread
    * @param securityDomainName
    */
   public static SecurityContext establishSecurityContext(String securityDomainName)
   { 
      SecurityContext securityContext = null;
      try
      {
         securityContext = SecurityContextFactory.createSecurityContext(securityDomainName);
      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      }
      SecurityActions.setSecurityContext(securityContext);
      return securityContext;
   }
   
   /**
    * <p>
    * Set the Log4J logger Plugin on the system property
    * <b>org.jboss.logging.Logger.pluginClass</b>
    * This is the default behavior of the {@code SecurityFactory#prepare()} method
    * </p>
    * <p>
    * <b>Note:</b> If the system property is already set, there is no change in the system property. 
    * </p>
    */ 
   public static void setLog4JLogger()
   { 
      String loggerPluginClass = SecurityActions.getSystemProperty("org.jboss.logging.Logger.pluginClass", "");
      if(loggerPluginClass.length() < 1)
         SecurityActions.setSystemProperty("org.jboss.logging.Logger.pluginClass", "org.jboss.logging.log4j.Log4jLoggerPlugin");
   }
   
   /**
    * <p>
    * Set the JDK logger Plugin on the system property
    * <b>org.jboss.logging.Logger.pluginClass</b> 
    * </p>
    * <p>
    * <b>Note:</b> If the system property is already set, there is no change in the system property. Also
    * you will need to provide logging.properties
    * </p>
    */ 
   public static void setJDKLogger()
   { 
      String loggerPluginClass = SecurityActions.getSystemProperty("org.jboss.logging.Logger.pluginClass", "");
      if(loggerPluginClass.length() < 1)
      {
         SecurityActions.setSystemProperty("org.jboss.logging.Logger.pluginClass", "org.jboss.logging.jdk.JDK14LoggerPlugin");
         SecurityActions.setSystemProperty("java.util.logging.config.file=logging.properties", "logging.properties");
      }  
   }
   
   /**
    * Will release anything that was done during {@link #prepare()} step
    */
   public static void release()
   {
      Configuration config = Configuration.getConfiguration();
      if(config == standaloneConfiguration)
      {
         Configuration.setConfiguration(parentConfiguration); //Set back the previously valid configuration
      }
   }
   
   private static void validate()
   {
      assert(securityManagement != null);
   }
}