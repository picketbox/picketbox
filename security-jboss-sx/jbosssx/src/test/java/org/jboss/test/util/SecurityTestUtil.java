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
package org.jboss.test.util;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jboss.security.SecurityConstants;
import org.jboss.security.authorization.ResourceType;
import org.jboss.security.authorization.config.AuthorizationModuleEntry;
import org.jboss.security.authorization.modules.DelegatingAuthorizationModule;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.AuthorizationInfo;
import org.jboss.security.config.SecurityConfiguration;
import org.jboss.security.identity.Role;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.identity.plugins.SimpleRole;
import org.jboss.security.identity.plugins.SimpleRoleGroup;
import org.jboss.test.authorization.web.TestWebAuthorizationModuleDelegate;

/**
 *  Util Class
 *  @author Anil.Saldhana@redhat.com
 *  @since  Apr 18, 2008 
 *  @version $Revision$
 */
public class SecurityTestUtil
{   
   public static RoleGroup getRoleGroup(String[] roles)
   {
      SimpleRoleGroup srg = new SimpleRoleGroup(SecurityConstants.ROLES_IDENTIFIER);

      List<Role> roleList = srg.getRoles(); 
      
      for(String role:roles)
      {
         roleList.add(new SimpleRole(role));   
      }
      return srg;
   }
   
   public static RoleGroup getRoleGroup(String rolename)
   {
      SimpleRoleGroup srg = new SimpleRoleGroup(SecurityConstants.ROLES_IDENTIFIER);
      srg.getRoles().add(new SimpleRole(rolename));
      return srg;
   }
   
   public static ApplicationPolicy getApplicationPolicy(String domain,
         Map<String,Object> moduleOptions)
   {
      AuthorizationInfo ai = new AuthorizationInfo(domain);
      String moduleName = DelegatingAuthorizationModule.class.getName();
      AuthorizationModuleEntry ame;
      
      if(moduleOptions != null)
         ame = new AuthorizationModuleEntry(moduleName, moduleOptions);
      else
         ame = new AuthorizationModuleEntry(moduleName);
      
      ai.add(ame);
      ApplicationPolicy ap = new ApplicationPolicy(domain);
      ap.setAuthorizationInfo(ai);
      return ap;
   }
   
   public static Map<String,Object> getWebDelegateOptions()
   {
      Map<String,Object> options = new HashMap<String,Object>();
      options.put("delegateMap", 
            ResourceType.WEB.toString() 
            + "=" 
            + TestWebAuthorizationModuleDelegate.class.getName());
      return options;
   }
    
   public static void setUpRegularConfiguration(ApplicationPolicy ap) throws Exception
   { 
      SecurityConfiguration.addApplicationPolicy(ap);
   } 
}