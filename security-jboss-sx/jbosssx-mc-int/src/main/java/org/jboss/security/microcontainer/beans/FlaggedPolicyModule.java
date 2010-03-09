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

import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;

/**
 * <p>
 * This class represents a flagged module, that is, a module that has a flag used to control the overall execution
 * process. For example, the authentication login-modules specify a flag to indicate whether each module is required or
 * not to succeed in order for the overall authentication process to be successful.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class FlaggedPolicyModule extends BasePolicyModule
{

   /** String representation of the control flag. */
   protected String flag;

   /** Login module control flag. */
   protected LoginModuleControlFlag controlFlag;

   /**
    * <p>
    * Obtains the control flag of the login module.
    * </p>
    * 
    * @return a {@code String} representing the control flag.
    */
   public String getFlag()
   {
      return flag;
   }

   /**
    * <p>
    * Sets the control flag of the login module.
    * </p>
    * 
    * @param flag a {@code String} representing the control flag to be set.
    */
   public void setFlag(String flag)
   {
      if (flag == null)
         flag = "required";
      
      // set the control flag using the string representation specified.
      flag = flag.toLowerCase();
      if (AppConfigurationEntry.LoginModuleControlFlag.REQUIRED.toString().indexOf(flag) > 0)
         this.controlFlag = AppConfigurationEntry.LoginModuleControlFlag.REQUIRED;
      else if (AppConfigurationEntry.LoginModuleControlFlag.REQUISITE.toString().indexOf(flag) > 0)
         this.controlFlag = AppConfigurationEntry.LoginModuleControlFlag.REQUISITE;
      else if (AppConfigurationEntry.LoginModuleControlFlag.SUFFICIENT.toString().indexOf(flag) > 0)
         this.controlFlag = AppConfigurationEntry.LoginModuleControlFlag.SUFFICIENT;
      else if (AppConfigurationEntry.LoginModuleControlFlag.OPTIONAL.toString().indexOf(flag) > 0)
         this.controlFlag = AppConfigurationEntry.LoginModuleControlFlag.OPTIONAL;
      else
         throw new IllegalArgumentException("Invalid module flag: " + flag);

      this.flag = flag;
   }

   /**
    * <p>
    * Utility method that creates an {@code AppConfigurationEntry} object using the information contained in this bean.
    * </p>
    * 
    * @return a reference to the {@code AppConfigurationEntry} that has been constructed.
    */
   public AppConfigurationEntry getAppConfigurationEntry()
   {
      return new AppConfigurationEntry(super.code, this.controlFlag, super.options);
   }

   /*
    * (non-Javadoc)
    * 
    * @see java.lang.Object#toString()
    */
   @Override
   public String toString()
   {
      StringBuffer buffer = new StringBuffer();
      buffer.append("Login module class: " + super.code);
      buffer.append("\nLogin module flag: " + this.flag);
      buffer.append("\nLogin module options: \n");
      for (Map.Entry<String, Object> entry : super.options.entrySet())
         buffer.append("\tname= " + entry.getKey() + ", value= " + entry.getValue() + "\n");
      return buffer.toString();
   }
}
