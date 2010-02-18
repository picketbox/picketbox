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

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.naming.Context;
import javax.security.auth.AuthPermission;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.AppConfigurationEntry;

import org.jboss.security.config.BaseSecurityInfo;

/**
 * The login module configuration information.
 * 
 * @author Scott.Stark@jboss.org
 * @version $Revision$
 */
public class AuthenticationInfo extends BaseAuthenticationInfo
{
   public static final AuthPermission GET_CONFIG_ENTRY_PERM = new AuthPermission("getLoginConfiguration");

   public static final AuthPermission SET_CONFIG_ENTRY_PERM = new AuthPermission("setLoginConfiguration");

   private CallbackHandler callbackHandler;

   public AuthenticationInfo()
   {
      this(null);
   }

   public AuthenticationInfo(String name)
   {
      this.name = name;
   }

   public void addAppConfigurationEntry(AppConfigurationEntry entry)
   {
      moduleEntries.add(entry);
   }

   /**
    * Set an application authentication configuration. This requires an AuthPermission("setLoginConfiguration") access.
    */
   public void setAppConfigurationEntry(AppConfigurationEntry[] loginModules)
   {
      SecurityManager sm = System.getSecurityManager();
      if (sm != null)
         sm.checkPermission(SET_CONFIG_ENTRY_PERM);

      moduleEntries.addAll(Arrays.asList(loginModules));
   }
   
   public void setAppConfigurationEntry(List<AppConfigurationEntry> listOfEntries)
   {
      SecurityManager sm = System.getSecurityManager();
      if (sm != null)
         sm.checkPermission(SET_CONFIG_ENTRY_PERM);

      moduleEntries.addAll(listOfEntries);
   }

   /**
    */
   public CallbackHandler getAppCallbackHandler()
   {
      return callbackHandler;
   }

   public void setAppCallbackHandler(CallbackHandler handler)
   {
      this.callbackHandler = handler;
   }

   @Override
   @SuppressWarnings("unchecked")
   public String toString()
   {
      StringBuffer buffer = new StringBuffer("AppConfigurationEntry[]:\n");
      for (int i = 0; i < moduleEntries.size(); i++)
      {
         AppConfigurationEntry entry = (AppConfigurationEntry) moduleEntries.get(i);
         buffer.append("[" + i + "]");
         buffer.append("\nLoginModule Class: " + entry.getLoginModuleName());
         buffer.append("\nControlFlag: " + entry.getControlFlag());
         buffer.append("\nOptions:\n");
         Map<String, ?> options = entry.getOptions();
         Iterator iter = options.entrySet().iterator();
         while (iter.hasNext())
         {
            Entry e = (Entry) iter.next();
            String name = (String) e.getKey();
            String value = e.getValue().toString();
            if (name.toLowerCase().equals("password") || name.toLowerCase().equals("bindcredential")
                  || name.toLowerCase().equals(Context.SECURITY_CREDENTIALS))
               value = "****";
            buffer.append("name=" + name);
            buffer.append(", value=" + value);
            buffer.append("\n");
         }
      }
      return buffer.toString();
   }

   @Override
   protected BaseSecurityInfo<Object> create(String name)
   {
      return new AuthenticationInfo(name);
   }
}
