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

import javax.security.auth.login.AppConfigurationEntry;

import org.jboss.security.auth.login.AuthenticationInfo;
import org.jboss.security.auth.login.BaseAuthenticationInfo;

/**
 * <p>
 * This class represents an authentication policy. An authentication policy describes the mechanisms and modules that
 * must be used in order to authenticate the users when they attempt to access a resource that is protected by a
 * security domain.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class AuthenticationPolicyBean extends BaseAuthenticationPolicy<FlaggedPolicyModule>
{

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.microcontainer.beans.BaseAuthenticationPolicy#getPolicyInfo(java.lang.String)
    */
   @Override
   public BaseAuthenticationInfo getPolicyInfo(String domainName)
   {
      AppConfigurationEntry[] entries = new AppConfigurationEntry[this.modules.size()];
      int entryIndex = 0;
      for (FlaggedPolicyModule moduleBean : this.modules)
         entries[entryIndex++] = moduleBean.getAppConfigurationEntry();

      AuthenticationInfo info = new AuthenticationInfo(domainName);
      info.setAppConfigurationEntry(entries);
      return info;
   }

   /*
    * (non-Javadoc)
    * 
    * @see java.lang.Object#toString()
    */
   @Override
   public String toString()
   {
      StringBuffer buffer = new StringBuffer("Authentication Policy:\n");
      for (int i = 0; i < super.modules.size(); i++)
      {
         FlaggedPolicyModule module = super.modules.get(i);
         buffer.append("Module[" + i + "]\n");
         buffer.append(module.toString());
      }
      return buffer.toString();
   }
}
