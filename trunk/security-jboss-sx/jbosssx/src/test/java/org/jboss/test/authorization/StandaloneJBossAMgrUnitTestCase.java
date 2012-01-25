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
package org.jboss.test.authorization;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;

import junit.framework.TestCase;

import org.jboss.security.SecurityConstants;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.callback.AppCallbackHandler;
import org.jboss.security.authorization.AuthorizationContext;
import org.jboss.security.authorization.Resource;
import org.jboss.security.authorization.ResourceType;
import org.jboss.security.authorization.config.AuthorizationModuleEntry;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.AuthorizationInfo;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.identity.plugins.SimpleRole;
import org.jboss.security.identity.plugins.SimpleRoleGroup;
import org.jboss.security.plugins.JBossAuthorizationManager;
import org.jboss.security.plugins.authorization.JBossAuthorizationContext;

//$Id$

/**
 *  Unit Test the JBoss Authorization Manager
 *  as a stand alone entity
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jan 3, 2008 
 *  @version $Revision$
 */
public class StandaloneJBossAMgrUnitTestCase extends TestCase
{
   public void testAuthorizationWithInjectedCtx() throws Exception
   {
      JBossAuthorizationManager jam = new JBossAuthorizationManager("test");
      Subject subject = new Subject();
      subject.getPrincipals().add(new SimplePrincipal("anil"));
      jam.setAuthorizationContext(getTestAuthorizationContext("test", subject));
      
      final HashMap<String, Object> cmap = new HashMap<String,Object>();
      Resource testResource = new Resource()
      {
         HashMap<String,Object> contextMap = new HashMap<String,Object>();
         
         public ResourceType getLayer()
         {
            return ResourceType.WEB;
         }

         public Map<String, Object> getMap()
         {
            return Collections.unmodifiableMap(cmap);
         }

         public void add(String key, Object value)
         {
            contextMap.put(key, value);
         }
      }; 
      assertEquals(AuthorizationContext.PERMIT, jam.authorize(testResource, subject, getRoleGroup()));
   }
     
   private AuthorizationContext getTestAuthorizationContext(String name,Subject subject)
   {
      JBossAuthorizationContext jac = new JBossAuthorizationContext(name,subject,
            new AppCallbackHandler("anil", "anilpass".toCharArray()));
      jac.setApplicationPolicy(getTestApplicationPolicy());
      return jac;
   }
   
   private ApplicationPolicy getTestApplicationPolicy()
   {
      ApplicationPolicy ap = new ApplicationPolicy("test");
      AuthorizationInfo authorizationInfo = new AuthorizationInfo("test");
      String moduleName = TestAuthorizationModule.class.getName();
      AuthorizationModuleEntry ame = new AuthorizationModuleEntry(moduleName); 
      authorizationInfo.add(ame);
      ap.setAuthorizationInfo(authorizationInfo);
      return ap;
   }
   
   private RoleGroup getRoleGroup()
   {
      RoleGroup rg = new SimpleRoleGroup(SecurityConstants.ROLES_IDENTIFIER);
      rg.addRole(new SimpleRole("ServletUserRole")); 
      return rg;
   }
}