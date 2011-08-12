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

import javax.security.auth.message.AuthException;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.AuthConfigProvider;
import javax.security.auth.message.config.RegistrationListener;
import javax.security.auth.message.config.AuthConfigFactory.RegistrationContext;

import org.jboss.logging.Logger;

//$Id$

/**
 *  Delegate that handles the AuthProvider registration for a 
 *  layer and an Application Context
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @since  May 15, 2006 
 *  @version $Revision$
 */
public class AuthProviderRegistrationDelegate
{
   private static Logger log = Logger.getLogger(AuthProviderRegistrationDelegate.class);
   
   //TODO: Improve the data structures
   
   /**
    * Map of String key to provider
    */
   private Map<String,AuthConfigProvider> keyProviderMap = new HashMap<String,AuthConfigProvider>();
   
   /**
    * Map of key to listener 
    */
   private Map<String,RegistrationListener> keyListenerMap = new HashMap<String,RegistrationListener>();
   
   /**
    * Map of registration id to description
    */
   private Map<String,String> idToDescriptionMap = new HashMap<String,String>();
   
   /**
    * Map of registration id to key  
    */
   private Map<String,String> idKeyMap = new HashMap<String,String>();
   
   /**
    * Map of provider to a list of registration ids
    */
   private Map<AuthConfigProvider,List<String>> providerToIDListMap = 
      new HashMap<AuthConfigProvider,List<String>>(); 
   
   
   public AuthProviderRegistrationDelegate()
   { 
   }
   
   /**
    * @see AuthConfigFactory#detachListener(RegistrationListener, String, String)
    */
   @SuppressWarnings({"unchecked", "rawtypes"})
   public String[] detachListener(RegistrationListener listener, String layer, 
         String appContext)
   { 
      if(listener == null)
         throw new IllegalArgumentException("listener is null");
      String[] arr = new String[0]; 
      String input = (layer + "_" + appContext).toUpperCase();
      String allLayer  = ("NULL" + "_" + appContext).toUpperCase(); 
      String allContext = (layer + "_" + "NULL").toUpperCase();
      String general = "NULL" + "_" + "NULL"; 
      
      RegistrationListener origListener = null;
      String key = null;
      for(int i = 0 ; i < 4 && origListener == null; i++)
      {
         if(i == 0) key = input;
         if(i == 1) key = allLayer;
         if(i == 2) key = allContext;
         if(i == 3) key = general;
         origListener = (RegistrationListener)keyListenerMap.get(key);
      } 
      
      if(origListener == listener)
      {
         keyListenerMap.remove(key);
         //Get the ID List
         AuthConfigProvider provider = (AuthConfigProvider)keyProviderMap.get(key);
         if(provider != null)
         {
            List list = (List)providerToIDListMap.get(provider);
            arr = new String[list.size()];
            list.toArray(arr);
         }
      } 
      return arr;   
   }
   
   /**
    * @see AuthConfigFactory#getConfigProvider(String, String, RegistrationListener)
    */ 
   public AuthConfigProvider getConfigProvider(String layer, String appContext, 
         RegistrationListener listener)
   { 
      if(appContext == null)
         appContext = " ";
      String input = (layer + "_" + appContext).toUpperCase();
      String allLayer  = ("NULL" + "_" + appContext).toUpperCase(); 
      String allContext = (layer + "_" + "NULL").toUpperCase();
      String general = "NULL" + "_" + "NULL";
      String blank = (layer + "_" + " ").toUpperCase();
      
      AuthConfigProvider acp = null;
      String key = null;
      for(int i = 0 ; i < 5 && acp == null; i++)
      {
         if(i == 0) key = input;
         if(i == 1) key = allLayer;
         if(i == 2) key = allContext;
         if(i == 3) key = general;
         if(i == 4) key = blank;
         acp = (AuthConfigProvider)keyProviderMap.get(key);
      }  
      if(acp != null && listener != null)
        this.keyListenerMap.put(key,listener);
      
      return acp;
   }
   
   /**
    * @see AuthConfigFactory#getRegistrationContext(String)
    */
   public RegistrationContext getRegistrationContext(String registrationID)
   { 
      final String description = (String)idToDescriptionMap.get(registrationID);
      String key = (String)idKeyMap.get(registrationID);
      StringTokenizer st = new StringTokenizer(key, "_");
      if(st.countTokens() < 2)
         throw new IllegalStateException("Invalid key obtained="+key);
      final String layer = st.nextToken();
      final String appCtx = st.nextToken();
      
      return new RegistrationContext()
      { 
         public String getAppContext()
         { 
            return appCtx.equals("NULL") ? null : appCtx;
         }

         public String getDescription()
         { 
            return description;
         }

         public String getMessageLayer()
         { 
            return layer.equals("NULL")? null : layer;
         }

		public boolean isPersistent() 
		{ 
			return false;
		} 
      };
   }
   
   /**
    * @see AuthConfigFactory#getRegistrationIDs(AuthConfigProvider)
    */
   @SuppressWarnings({"unchecked", "rawtypes"})
   public String[] getRegistrationIDs(AuthConfigProvider provider)
   {  
      List al = new ArrayList();
      if(provider == null)
      {
         al.addAll(idToDescriptionMap.keySet());  
      }
      else
      {
         List list = (List)this.providerToIDListMap.get(provider);
         if(list != null)
            al.addAll(list); 
      }
      String[] sarr = new String[al.size()];
      al.toArray(sarr);
      return sarr;
   }
   
   /**
    * @see AuthConfigFactory#registerConfigProvider(String, Map, String, String, String)
    */
   @SuppressWarnings({"unchecked", "rawtypes"})
   public String registerConfigProvider(String className, Map properties, 
         String layer, String appContext, String description)
   throws AuthException, SecurityException
   { 
      if(className == null || className.length() == 0)
         throw new IllegalArgumentException("className is null or zero length");
 
      //Instantiate the provider
      AuthConfigProvider acp = null;
      try
      {
         Class provClass = SecurityActions.getContextClassLoader().loadClass(className);
         Constructor ctr = provClass.getConstructor(new Class[] {Map.class});
         acp = (AuthConfigProvider)ctr.newInstance(new Object[] {properties});
      }
      catch(Exception e)
      {
        log.error("Cannot register provider:"+className+":",e);
        throw new AuthException("Cannot register Provider "+ className + ":reason="+e); 
      } 
      
      return this.registerConfigProvider(acp, layer, appContext, description); 
   }
   
   @SuppressWarnings({"unchecked", "rawtypes"})
   public String registerConfigProvider(AuthConfigProvider provider,
         String layer,  String appContext,  String description)
   {
      if(provider == null)
         throw new IllegalArgumentException("provider is null");
      
      StringBuilder key = new StringBuilder();  
      key.append(layer == null ? "NULL" : layer.toUpperCase());
      key.append("_");
      key.append(appContext == null ? "NULL" : appContext.toUpperCase());
      
      String keystr = key.toString();
      keyProviderMap.put(keystr,provider); 
      
      //Generate a GUID
      UUID guid = UUID.randomUUID();
      String providerID = guid.toString();
      this.idKeyMap.put(providerID, keystr);
      List list = (List)this.providerToIDListMap.get(provider);
      if(list == null) 
      {
         list = new ArrayList(); 
      }
      list.add(providerID);
      this.providerToIDListMap.put(provider,list); 
      if(description != null)
         this.idToDescriptionMap.put(providerID, description);
      
      //Check if their is a pre-existing listener
      RegistrationListener listener = (RegistrationListener)keyListenerMap.get(keystr);
      if(listener != null)
         listener.notify(layer,appContext);
      
      return providerID;  
   }
   
   /**
    * @see AuthConfigFactory#removeRegistration(String)
    */
   public boolean removeRegistration(String registrationID)
   { 
      if(registrationID == null)
         throw new IllegalArgumentException("registrationID is null");
      
      String key = (String)idKeyMap.get(registrationID);
      if(key != null)
      {
         RegistrationListener listener = (RegistrationListener)this.keyListenerMap.get(key);
         RegistrationContext rc = this.getRegistrationContext(registrationID);
         
         this.keyProviderMap.remove(key);
         //Notify the listener of the change
         if(listener != null)
            listener.notify(rc.getMessageLayer(),rc.getAppContext()); 
         return true;
      }
      return false;
   } 
}