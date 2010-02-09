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
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;

import junit.framework.TestCase;

import org.jboss.security.AnybodyPrincipal;
import org.jboss.security.SecurityConstants;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.authorization.AuthorizationContext;
import org.jboss.security.authorization.ResourceKeys;
import org.jboss.security.authorization.modules.ejb.EJBPolicyModuleDelegate;
import org.jboss.security.authorization.resources.EJBResource;
import org.jboss.security.identity.Role;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.identity.plugins.SimpleRole;
import org.jboss.security.identity.plugins.SimpleRoleGroup;
import org.jboss.security.javaee.SecurityRoleRef;
 

/**
 *  Unit Test for the EJB Policy Module Delegate
 *  @author Anil.Saldhana@redhat.com
 *  @since  Dec 20, 2007 
 *  @version $Revision$
 */
public class EJBPolicyModuleDelegateUnitTestCase extends TestCase
{ 
   /**
    * Test a successful authorization case
    */
   public void testEJBAuthorizationPass()
   {
      EJBPolicyModuleDelegate epmd = new EJBPolicyModuleDelegate();
       
      //Create a context map
      Map<String,Object> cmap = new HashMap<String,Object>(); 
      
      EJBResource resource = new EJBResource(cmap);
      resource.setPrincipal(new SimplePrincipal("AuthenticatedPrincipal"));
      resource.setEjbMethod(DummyClass.class.getDeclaredMethods()[0]);
      resource.setEjbName(DummyClass.class.getCanonicalName());
      resource.setEjbMethodRoles( getRoleGroup(new String[] {"gooduser"}) );
      
      assertEquals(AuthorizationContext.PERMIT,epmd.authorize(resource,
            new Subject(), 
            getRoleGroup(new String[]{"gooduser", "validuser" })) );
   } 
   
   /**
    * Test an unsuccessful authorization case
    */
   public void testEJBAuthorizationFail()
   {
      EJBPolicyModuleDelegate epmd = new EJBPolicyModuleDelegate(); 
      
      //Create a context map
      Map<String,Object> cmap = new HashMap<String,Object>();  
      
      EJBResource resource = new EJBResource(cmap);
      resource.setPrincipal(new SimplePrincipal("AuthenticatedPrincipal"));
      resource.setEjbMethod(DummyClass.class.getDeclaredMethods()[0]);
      resource.setEjbName(DummyClass.class.getCanonicalName());
      resource.setEjbMethodRoles( getRoleGroup(new String[] {"gooduser"}) );
      
      int res = epmd.authorize(resource, new Subject(), getRoleGroup(new String[]{"baduser"}));
      
      assertEquals(AuthorizationContext.DENY, res);
   }
   
   /**
    * Test the Unchecked method permissions
    */
   public void testEJBAuthorizationUnchecked()
   {
      EJBPolicyModuleDelegate epmd = new EJBPolicyModuleDelegate(); 
      
      //Create a context map
      Map<String,Object> cmap = new HashMap<String,Object>();  
      
      EJBResource resource = new EJBResource(cmap);
      resource.setPrincipal(new SimplePrincipal("AuthenticatedPrincipal"));
      resource.setEjbMethod(DummyClass.class.getDeclaredMethods()[0]);
      resource.setEjbName(DummyClass.class.getCanonicalName());
      resource.setEjbMethodRoles( getRoleGroup(new String[] {AnybodyPrincipal.ANYBODY}) );
      
      int res = epmd.authorize(resource, new Subject(), getRoleGroup(new String[]{"baduser"}));
      assertEquals(AuthorizationContext.PERMIT, res);
   } 
   
   /**
    * Test that in the absence of method roles sent, the authorization fails
    */
   public void testEJBAuthorizationMissingMethodRoles()
   {
      EJBPolicyModuleDelegate epmd = new EJBPolicyModuleDelegate();
     
      //Create a context map
      Map<String,Object> cmap = new HashMap<String,Object>();  
      
      EJBResource resource = new EJBResource(cmap);
      resource.setPrincipal(new SimplePrincipal("AuthenticatedPrincipal"));
      resource.setEjbMethod(DummyClass.class.getDeclaredMethods()[0]);
      resource.setEjbName(DummyClass.class.getCanonicalName()); 
      
      int res = epmd.authorize(resource, new Subject(), getRoleGroup(new String[]{"baduser"}));
      assertEquals(AuthorizationContext.DENY, res);
   } 
   
   /**
    * Test EJBContext.isCallerInRole (Success Case)
    */
   public void testIsCallerInRoleValid()
   {
      EJBPolicyModuleDelegate epmd = new EJBPolicyModuleDelegate();
      
      //Create a context map
      Map<String,Object> cmap = new HashMap<String,Object>(); 
      
      cmap.put(ResourceKeys.ROLEREF_PERM_CHECK, true);
      cmap.put(ResourceKeys.ROLENAME, "employee");
      
      EJBResource resource = new EJBResource(cmap);
      resource.setPrincipal(new SimplePrincipal("AuthenticatedPrincipal"));
      resource.setEjbMethod(DummyClass.class.getDeclaredMethods()[0]);
      resource.setEjbName(DummyClass.class.getCanonicalName());
      resource.setEjbMethodRoles( getRoleGroup(new String[] {"gooduser"}) );

      Set<SecurityRoleRef> roleRefSet = new HashSet<SecurityRoleRef>();
      roleRefSet.add(new SecurityRoleRef("employee", "gooduser"));
      resource.setSecurityRoleReferences(roleRefSet);
      
      int result = epmd.authorize(resource,
            new Subject(), 
            getRoleGroup(new String[]{"gooduser", "validuser" }));
      
      assertEquals(AuthorizationContext.PERMIT, result);
   }
   
   /**
    * Test EJBContext.isCallerInRole (Failure Case)
    */
   public void testIsCallerInRoleInvalid()
   {
      EJBPolicyModuleDelegate epmd = new EJBPolicyModuleDelegate();
      
      //Create a context map
      Map<String,Object> cmap = new HashMap<String,Object>(); 
      
      cmap.put(ResourceKeys.ROLEREF_PERM_CHECK, true);
      cmap.put(ResourceKeys.ROLENAME, "employee");
      
      EJBResource resource = new EJBResource(cmap);
      resource.setPrincipal(new SimplePrincipal("AuthenticatedPrincipal"));
      resource.setEjbMethod(DummyClass.class.getDeclaredMethods()[0]);
      resource.setEjbName(DummyClass.class.getCanonicalName());
      resource.setEjbMethodRoles( getRoleGroup(new String[] {"gooduser"}) );

      Set<SecurityRoleRef> roleRefSet = new HashSet<SecurityRoleRef>();
      roleRefSet.add(new SecurityRoleRef("employee", "baduser")); //Bad user
      resource.setSecurityRoleReferences(roleRefSet);
      
      int result = epmd.authorize(resource,
            new Subject(), 
            getRoleGroup(new String[]{"gooduser", "validuser" }));
      
      assertEquals(AuthorizationContext.DENY, result);
   }
   
   /**
    * Test EJB 1.1 EJBContext.isCallerInRole case
    */
   public void testIsCallerInRoleValidEJB11()
   {
      EJBPolicyModuleDelegate epmd = new EJBPolicyModuleDelegate();
      
      //Create a context map
      Map<String,Object> cmap = new HashMap<String,Object>(); 
      
      cmap.put(ResourceKeys.ROLEREF_PERM_CHECK, true);
      cmap.put(ResourceKeys.ROLENAME, "employee");
      
      EJBResource resource = new EJBResource(cmap);
      resource.setPrincipal(new SimplePrincipal("AuthenticatedPrincipal"));
      resource.setEjbMethod(DummyClass.class.getDeclaredMethods()[0]);
      resource.setEjbName(DummyClass.class.getCanonicalName());
      resource.setEjbMethodRoles( getRoleGroup(new String[] {"gooduser"}) );
      resource.setEnforceEJBRestrictions(true); //Enforce EJB 1.1

      Set<SecurityRoleRef> roleRefSet = new HashSet<SecurityRoleRef>();
      roleRefSet.add(new SecurityRoleRef("employee", "gooduser"));  
      resource.setSecurityRoleReferences(roleRefSet);

      int result = epmd.authorize(resource,
            new Subject(), 
            getRoleGroup(new String[]{"gooduser", "validuser" }));
      assertEquals(AuthorizationContext.PERMIT, result);
   }
   
   /**
    * Test EJB 1.1 EJBContext.isCallerInRole case
    */
   public void testIsCallerInRoleInvalidEJB11()
   {
      EJBPolicyModuleDelegate epmd = new EJBPolicyModuleDelegate();
      
      //Create a context map
      Map<String,Object> cmap = new HashMap<String,Object>(); 
      
      cmap.put(ResourceKeys.ROLEREF_PERM_CHECK, true);
      cmap.put(ResourceKeys.ROLENAME, "impostor");
      
      EJBResource resource = new EJBResource(cmap);
      resource.setPrincipal(new SimplePrincipal("AuthenticatedPrincipal"));
      resource.setEjbMethod(DummyClass.class.getDeclaredMethods()[0]);
      resource.setEjbName(DummyClass.class.getCanonicalName());
      resource.setEjbMethodRoles( getRoleGroup(new String[] {"gooduser"}) );
      resource.setEnforceEJBRestrictions(true); //Enforce EJB 1.1

      Set<SecurityRoleRef> roleRefSet = new HashSet<SecurityRoleRef>();
      roleRefSet.add(new SecurityRoleRef("employee", "baduser")); //Bad user
      resource.setSecurityRoleReferences(roleRefSet);
      
      try
      {
          epmd.authorize(resource,
               new Subject(), 
               getRoleGroup(new String[]{"gooduser", "validuser" }));
          fail("Should have thrown a RuntimeException due to ejb 1.1 restrictions");
      }
      catch(RuntimeException e)
      { //pass
      } 
      catch(Exception e)
      {
         fail("Test failed to obtain a run time exception, "+ e.getLocalizedMessage());
      }
   }
   
   /**
    * Create a RoleGroup given a set of roles
    * @param roles
    * @return
    */
   private RoleGroup getRoleGroup(String[] roles)
   {
      SimpleRoleGroup srg = new SimpleRoleGroup(SecurityConstants.ROLES_IDENTIFIER);

      List<Role> roleList = srg.getRoles(); 
      
      for(String role:roles)
      {
         roleList.add(new SimpleRole(role));   
      }
      return srg;
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