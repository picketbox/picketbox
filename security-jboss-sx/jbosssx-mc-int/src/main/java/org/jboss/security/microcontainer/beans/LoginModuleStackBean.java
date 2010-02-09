/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2008, Red Hat Middleware LLC, and individual contributors
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
package org.jboss.security.microcontainer.beans;

import java.util.ArrayList;
import java.util.List;

import javax.security.auth.login.AppConfigurationEntry;

import org.jboss.security.auth.login.LoginModuleStackHolder;

/**
 * <p>
 * This class represents a stack of login-modules that has been configured as part of a JASPI authentication policy.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class LoginModuleStackBean
{

   /** the name of the stack. */
   private String name;

   /** the login-modules that are part of the stack. */
   private List<FlaggedPolicyModule> loginModules;

   /**
    * <p>
    * Creates an instance of {@code LoginModuleStackBean}.
    * </p>
    */
   public LoginModuleStackBean()
   {
      this.loginModules = new ArrayList<FlaggedPolicyModule>();
   }

   /**
    * <p>
    * Obtains the name of the stack.
    * </p>
    * 
    * @return a {@code String} representing the name of the stack.
    */
   public String getName()
   {
      return name;
   }

   /**
    * <p>
    * Sets the name of the stack.
    * </p>
    * 
    * @param name a {@code String} representing the name to be set.
    */
   public void setName(String name)
   {
      this.name = name;
   }

   /**
    * <p>
    * Obtains the login-modules that form the stack.
    * </p>
    * 
    * @return a {@code List<FlaggedPolicyModule>} containing the login-modules.
    */
   public List<FlaggedPolicyModule> getLoginModules()
   {
      return loginModules;
   }

   /**
    * <p>
    * Sets the login-modules that form the stack.
    * </p>
    * 
    * @param loginModules a {@code List<FlaggedPolicyModule>} containing the modules to be set.
    */
   public void setLoginModules(List<FlaggedPolicyModule> loginModules)
   {
      this.loginModules = loginModules;
   }

   /**
    * <p>
    * Creates a {@code LoginModuleStackHolder} using the information contained in this bean.
    * </p>
    * 
    * @return the constructed {@code LoginModuleStackHolder}.
    */
   public LoginModuleStackHolder getLoginModuleStackHolder()
   {
      LoginModuleStackHolder holder = new LoginModuleStackHolder(this.name, new ArrayList<AppConfigurationEntry>());

      for (FlaggedPolicyModule module : this.loginModules)
         holder.addAppConfigurationEntry(module.getAppConfigurationEntry());

      return holder;
   }

   /*
    * (non-Javadoc)
    * 
    * @see java.lang.Object#toString()
    */
   @Override
   public String toString()
   {
      StringBuffer buffer = new StringBuffer("Login-Module Stack: " + this.name + "\n");
      for (int i = 0; i < this.loginModules.size(); i++)
      {
         FlaggedPolicyModule module = this.loginModules.get(i);
         buffer.append("Module[" + i + "]\n");
         buffer.append(module.toString());
      }
      return buffer.toString();
   }
}
