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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jboss.security.auth.container.config.AuthModuleEntry;
import org.jboss.security.auth.login.BaseAuthenticationInfo;
import org.jboss.security.auth.login.JASPIAuthenticationInfo;
import org.jboss.security.auth.login.LoginModuleStackHolder;

/**
 * <p>
 * This class represents a jaspi authentication policy. An authentication policy describes the mechanisms and modules
 * that must be used in order to authenticate the users when they attempt to access a resource that is protected by a
 * security domain.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class JASPIAuthenticationPolicyBean extends BaseAuthenticationPolicy<StackRefPolicyModule>
{

   /** the login-module stacks of the policy. */
   private List<LoginModuleStackBean> moduleStacks;

   /**
    * <p>
    * Created an instance of {@code JASPIAuthenticationPolicyBean}.
    * </p>
    */
   public JASPIAuthenticationPolicyBean()
   {
      this.moduleStacks = new ArrayList<LoginModuleStackBean>();
   }

   /**
    * <p>
    * Obtains the login-module stacks of the policy.
    * </p>
    * 
    * @return a {@code List<LoginModuleStackBean>} containing the policy's login-module stacks.
    */
   public List<LoginModuleStackBean> getModuleStacks()
   {
      return moduleStacks;
   }

   /**
    * <p>
    * Sets the login-module stacks of the policy.
    * </p>
    * 
    * @param moduleStacks a {@code List<LoginModuleStackBean>} containing the stacks to be set.
    */
   public void setModuleStacks(List<LoginModuleStackBean> moduleStacks)
   {
      this.moduleStacks = moduleStacks;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.microcontainer.beans.BasePolicyBean#getPolicyInfo(java.lang.String)
    */
   @Override
   public BaseAuthenticationInfo getPolicyInfo(String domainName)
   {
      JASPIAuthenticationInfo info = new JASPIAuthenticationInfo(domainName);
      Map<String, LoginModuleStackHolder> stackMap = new HashMap<String, LoginModuleStackHolder>();

      // add the stack modules to the authentication info.
      for (LoginModuleStackBean stackBean : this.moduleStacks)
      {
         LoginModuleStackHolder holder = stackBean.getLoginModuleStackHolder();
         info.add(holder);
         stackMap.put(stackBean.getName(), holder);
      }

      // add the auth modules to the authentication info.
      for (StackRefPolicyModule module : super.modules)
      {
         AuthModuleEntry entry = new AuthModuleEntry(module.getCode(), module.getOptions(), module.getStackRef());
         entry.setLoginModuleStackHolder(stackMap.get(module.getStackRef()));
         info.add(entry);
      }

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
      StringBuffer buffer = new StringBuffer("JASPI-Authentication Policy:\n");
      // string representation of the auth-modules.
      for (int i = 0; i < super.modules.size(); i++)
      {
         StackRefPolicyModule module = super.modules.get(i);
         buffer.append("Module[" + i + "]\n");
         buffer.append(module.toString());
      }
      // string representation of the login-module stacks.
      for (LoginModuleStackBean stackBean : this.moduleStacks)
         buffer.append(stackBean.toString());
      return buffer.toString();
   }
}
