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
package org.jboss.test.authorization.ejb;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;

import junit.framework.TestCase;

import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.callback.AppCallbackHandler;
import org.jboss.security.authorization.AuthorizationContext;
import org.jboss.security.authorization.AuthorizationException;
import org.jboss.security.authorization.ResourceKeys;
import org.jboss.security.authorization.resources.EJBResource;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.javaee.SecurityRoleRef;
import org.jboss.security.plugins.authorization.JBossAuthorizationContext;
import org.jboss.test.util.SecurityTestUtil;


/**
 *  EJB Authorization Unit Test Case
 *  @author Anil.Saldhana@redhat.com
 *  @since  Nov 26, 2007 
 *  @version $Revision$
 */
public class EJBAuthorizationUnitTestCase extends TestCase
{
   protected void setUp() throws Exception
   { 
      ApplicationPolicy ap = SecurityTestUtil.getApplicationPolicy("test", null);
      SecurityTestUtil.setUpRegularConfiguration(ap);
   }
   
   /**
    * Test EJB Authorization.
    * TestEJB is an ejb that has a method "void someMethod()"
    * which is usable by roles (roleA,roleB)
    * @throws Exception 
    */
   public void testRegularEJBAuthorizationPass() throws Exception
   {   
      RoleGroup principalRole = SecurityTestUtil.getRoleGroup(new String[] {"roleA"});
      
      //Create a ContextMap
      Map<String,Object> cmap = new HashMap<String,Object>();   
      
      EJBResource ejbResource = new EJBResource(cmap);
      ejbResource.setPrincipal(new SimplePrincipal("AuthenticatedPrincipal"));
      ejbResource.setEjbName("TestEJB");
      ejbResource.setEjbMethod(DummyClass.class.getMethod("someMethod", new Class[0]));
      ejbResource.setEjbMethodInterface("void someMethod");
      ejbResource.setEjbMethodRoles(SecurityTestUtil.getRoleGroup(new String[]{"roleA", "roleC"}));      
      
      AuthorizationContext ac = new JBossAuthorizationContext("test",
            new AppCallbackHandler("a","b".toCharArray()));
      int result = ac.authorize(ejbResource, new Subject(), principalRole);
      assertEquals(AuthorizationContext.PERMIT, result);  
   }
   
   /**
    * Test EJB Authorization.
    * TestEJB is an ejb that has a method "void someMethod()"
    * which is usable by roles (roleA,roleB)
    * 
    * This method tests with a bad role
    * @throws Exception 
    */
   public void testInvalidRegularEJBAuthorization() throws Exception
   {
      RoleGroup principalRole = SecurityTestUtil.getRoleGroup(new String[] {"badRole"});
       
      //Create a ContextMap
      Map<String,Object> cmap = new HashMap<String,Object>();  
      
      EJBResource ejbResource = new EJBResource(cmap);
      ejbResource.setEjbName("TestEJB");
      ejbResource.setEjbMethod(DummyClass.class.getMethod("someMethod", new Class[0]));
      ejbResource.setEjbMethodInterface("void someMethod");
      ejbResource.setEjbMethodRoles(SecurityTestUtil.getRoleGroup(new String[]{"roleA", "roleC"})); 
      
      AuthorizationContext ac = new JBossAuthorizationContext("test",
             new AppCallbackHandler("a","b".toCharArray()));
      try
      {
         ac.authorize(ejbResource, new Subject(), principalRole);
         fail("Should have failed");
      }
      catch(AuthorizationException ignore)
      {   
      }
      catch(Exception e)
      {
         fail(e.getLocalizedMessage());
      }
   }
   
   public void testSecurityRoleRef() throws Exception
   { 
      RoleGroup principalRole = SecurityTestUtil.getRoleGroup(new String[] {"roleA"});
      
      //Create a ContextMap
      Map<String,Object> cmap = new HashMap<String,Object>();  
      
      EJBResource ejbResource = new EJBResource(cmap);
      ejbResource.setEjbName("TestEJB");
      ejbResource.setEjbMethod(DummyClass.class.getMethod("someMethod", new Class[0]));
      ejbResource.setEjbMethodInterface("void someMethod");
      ejbResource.setEjbMethodRoles(SecurityTestUtil.getRoleGroup(new String[]{"roleA"}));
      //For Security Role Refs, we check that there is a principal
      ejbResource.setPrincipal(new SimplePrincipal("SomePrincipal"));
     
      //Additional entries needed for role ref
      Set<SecurityRoleRef> roleRefSet = new HashSet<SecurityRoleRef>();
      SecurityRoleRef srr = new SecurityRoleRef( "roleLink", "roleA", "something");
      roleRefSet.add(srr);
      ejbResource.setSecurityRoleReferences(roleRefSet);
      
      cmap.put(ResourceKeys.ROLEREF_PERM_CHECK, Boolean.TRUE); 
      cmap.put(ResourceKeys.ROLENAME, "roleLink");
      
      AuthorizationContext ac = new JBossAuthorizationContext("test",
            new AppCallbackHandler("a","b".toCharArray()));
      int result = ac.authorize(ejbResource, new Subject(), principalRole);
      assertEquals(AuthorizationContext.PERMIT, result);
   }
   
   /**
    * Dummy Class just to get a Method instance
    * by calling DummyClass.class.getMethod()
    * @author asaldhana
    *
    */
   public class DummyClass
   {
      public void someMethod(){}
   }
}