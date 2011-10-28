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
package org.jboss.security.auth.message.config;

import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.UUID;

import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.AuthConfigProvider;
import javax.security.auth.message.config.RegistrationListener;

import org.jboss.logging.Logger;
import org.jboss.security.ErrorCodes;

//$Id$

/**
 * Default Authentication Configuration Factory
 * 
 * @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 * @since May 15, 2006
 * @version $Revision$
 */
public class JBossAuthConfigFactory extends AuthConfigFactory
{
   private static Logger log = Logger.getLogger(JBossAuthConfigFactory.class);

   /**
    * Map of String key to provider
    */
   private Map<String, AuthConfigProvider> keyProviderMap = new HashMap<String, AuthConfigProvider>();

   /**
    * Map of key to listener
    */
   private Map<String, RegistrationListener> keyListenerMap = new HashMap<String, RegistrationListener>();

   /**
    * Map of registration id to description
    */
   private Map<String, String> idToDescriptionMap = new HashMap<String, String>();

   /**
    * Map of registration id to key
    */
   private Map<String, String> idKeyMap = new HashMap<String, String>();

   /**
    * Map of provider to a list of registration ids
    */
   private Map<AuthConfigProvider, List<String>> providerToIDListMap = new HashMap<AuthConfigProvider, List<String>>();

   /**
    * <p>
    * Creates an instance of {@code JBossAuthConfigFactory}.
    * </p>
    */
   public JBossAuthConfigFactory()
   {
      Map<String, Object> props = new HashMap<String, Object>();
      JBossAuthConfigProvider provider = new JBossAuthConfigProvider(props, null);
      // register a few default providers for the layers
      this.registerConfigProvider(provider, "HTTP", null, "Default Provider");
      this.registerConfigProvider(provider, "HttpServlet", null, "Default Provider");
   }

   /*
    * (non-Javadoc)
    * @see javax.security.auth.message.config.AuthConfigFactory#detachListener(javax.security.auth.message.config.RegistrationListener, java.lang.String, java.lang.String)
    */
   public String[] detachListener(RegistrationListener listener, String layer, String appContext)
   { 
      if (listener == null)
         throw new IllegalArgumentException(ErrorCodes.NULL_ARGUMENT + "listener");

      String[] arr = new String[0];
      String input = layer + "^" + appContext;
      String allLayer = "null" + "^" + appContext;
      String allContext = layer + "^" + "null";
      String general = "null" + "^" + "null";

      RegistrationListener origListener = null;
      String key = null;
      for (int i = 0; i < 4 && origListener == null; i++)
      {
         if (i == 0)
            key = input;
         if (i == 1)
            key = allLayer;
         if (i == 2)
            key = allContext;
         if (i == 3)
            key = general;
         origListener = (RegistrationListener) keyListenerMap.get(key);
      }

      if (origListener == listener)
      {
         keyListenerMap.remove(key);
         // Get the ID List
         AuthConfigProvider provider = (AuthConfigProvider) keyProviderMap.get(key);
         if (provider != null)
         {
            List<String> list = providerToIDListMap.get(provider);
            arr = new String[list.size()];
            list.toArray(arr);
         }
      }
      return arr;
   }

   /*
    * (non-Javadoc)
    * @see javax.security.auth.message.config.AuthConfigFactory#getConfigProvider(java.lang.String, java.lang.String, javax.security.auth.message.config.RegistrationListener)
    */
   public AuthConfigProvider getConfigProvider(String layer, String appContext, RegistrationListener listener)
   {
      if (appContext == null)
         appContext = " ";
      String input = layer + "^" + appContext;
      String allLayer = "null" + "^" + appContext;
      String allContext = layer + "^" + "null";
      String general = "null" + "^" + "null";

      AuthConfigProvider acp = null;
      String key = null;
      for (int i = 0; i < 4 && acp == null; i++)
      {
         if (i == 0)
            key = input;
         if (i == 1)
            key = allLayer;
         if (i == 2)
            key = allContext;
         if (i == 3)
            key = general;
         acp = (AuthConfigProvider) keyProviderMap.get(key);
      }
      
      if (acp != null && listener != null)
         this.keyListenerMap.put(key, listener);

      return acp;
   }

   /*
    * (non-Javadoc)
    * @see javax.security.auth.message.config.AuthConfigFactory#getRegistrationContext(java.lang.String)
    */
   public RegistrationContext getRegistrationContext(String registrationID)
   {
      String key = (String) idKeyMap.get(registrationID);
      StringTokenizer st = new StringTokenizer(key, "^");
      if (st.countTokens() < 2)
         throw new IllegalStateException(ErrorCodes.MISMATCH_SIZE + "Invalid key obtained=" + key);

      final String layer = st.nextToken();
      final String appCtx = st.nextToken();
      final String description = (String) idToDescriptionMap.get(registrationID);

      return new RegistrationContext()
      {
         public String getAppContext()
         {
            return appCtx.equals("null") ? null : appCtx;
         }

         public String getDescription()
         {
            return description;
         }

         public String getMessageLayer()
         {
            return layer.equals("null") ? null : layer;
         }

         public boolean isPersistent()
         {
            return false;
         }
      };
   }

   /*
    * (non-Javadoc)
    * @see javax.security.auth.message.config.AuthConfigFactory#getRegistrationIDs(javax.security.auth.message.config.AuthConfigProvider)
    */
   public String[] getRegistrationIDs(AuthConfigProvider provider)
   {
      List<String> al = new ArrayList<String>();
      if (provider == null)
      {
         al.addAll(idKeyMap.keySet());
      }
      else
      {
         List<String> list = this.providerToIDListMap.get(provider);
         if (list != null)
            al.addAll(list);
      }
      String[] sarr = new String[al.size()];
      al.toArray(sarr);
      return sarr;
   }

   /*
    * (non-Javadoc)
    * @see javax.security.auth.message.config.AuthConfigFactory#refresh()
    */
   public void refresh()
   {
   }

   /*
    * (non-Javadoc)
    * @see javax.security.auth.message.config.AuthConfigFactory#registerConfigProvider(java.lang.String, java.util.Map, java.lang.String, java.lang.String, java.lang.String)
    */
   @SuppressWarnings("rawtypes")
   public String registerConfigProvider(String className, Map properties, String layer, String appContext,
         String description)
   {
      if (className == null || className.length() == 0)
         throw new IllegalArgumentException(ErrorCodes.NULL_ARGUMENT + "className is null or zero length");

      // Instantiate the provider
      AuthConfigProvider acp = null;
      try
      {
         // An AuthConfigProvider must have a two-argument constructor (Map properties, AuthConfigFactory factory). 
         Class<?> provClass = SecurityActions.getContextClassLoader().loadClass(className);
         Constructor<?> ctr = provClass.getConstructor(new Class[] {Map.class, AuthConfigFactory.class});
         acp = (AuthConfigProvider) ctr.newInstance(new Object[] {properties, null});
      }
      catch (Exception e)
      {
         log.error("Cannot register provider:" + className + ":", e);
         throw new SecurityException(ErrorCodes.CANNOT_REGISTER_PROVIDER + className + ":reason=" + e);
      }

      return this.registerConfigProvider(acp, layer, appContext, description);
   }

   /*
    * (non-Javadoc)
    * @see javax.security.auth.message.config.AuthConfigFactory#registerConfigProvider(javax.security.auth.message.config.AuthConfigProvider, java.lang.String, java.lang.String, java.lang.String)
    */
   public String registerConfigProvider(AuthConfigProvider provider, String layer, String appContext, String description)
   {
      if (provider == null)
         throw new IllegalArgumentException(ErrorCodes.NULL_ARGUMENT + "provider");

      StringBuilder key = new StringBuilder();
      key.append(layer == null ? "null" : layer);
      key.append("^");
      key.append(appContext == null ? "null" : appContext);

      String keystr = key.toString();
      keyProviderMap.put(keystr, provider);

      // Generate a GUID
      UUID guid = UUID.randomUUID();
      String providerID = guid.toString();
      this.idKeyMap.put(providerID, keystr);

      List<String> list = this.providerToIDListMap.get(provider);
      if (list == null)
         list = new ArrayList<String>();
      list.add(providerID);

      this.providerToIDListMap.put(provider, list);
      if (description != null)
         this.idToDescriptionMap.put(providerID, description);

      // Check if their is a pre-existing listener
      RegistrationListener listener = keyListenerMap.get(keystr);
      if (listener != null)
         listener.notify(layer, appContext);

      return providerID;
   }

   /*
    * (non-Javadoc)
    * @see javax.security.auth.message.config.AuthConfigFactory#removeRegistration(java.lang.String)
    */
   public boolean removeRegistration(String registrationID)
   {
      if (registrationID == null)
         throw new IllegalArgumentException(ErrorCodes.NULL_ARGUMENT + "registrationID");

      String key = idKeyMap.get(registrationID);
      if (key != null)
      {
         RegistrationListener listener = this.keyListenerMap.get(key);
         RegistrationContext rc = this.getRegistrationContext(registrationID);

         this.keyProviderMap.remove(key);
         // Notify the listener of the change
         if (listener != null)
            listener.notify(rc.getMessageLayer(), rc.getAppContext());
         return true;
      }
      return false;
   }
}