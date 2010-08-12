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
package org.jboss.test.security.helpers;

import java.security.CodeSource;
import java.security.Principal;
import java.util.HashMap;

import javax.security.auth.Subject;

import junit.framework.TestCase;

import org.jboss.security.SecurityContext;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.authorization.resources.EJBResource;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.javaee.exceptions.MissingArgumentsException;
import org.jboss.security.plugins.JBossPolicyRegistration;
import org.jboss.security.plugins.JBossSecurityContext;
import org.jboss.security.plugins.javaee.EJBAuthorizationHelper;
import org.jboss.test.util.SecurityTestUtil;
 
/**
 *  Unit Test the EJBAuthorizationHelper
 *  @author Anil.Saldhana@redhat.com
 *  @since  Apr 18, 2008 
 *  @version $Revision$
 */
public class EJBAuthorizationHelperUnitTestCase extends TestCase
{
   private SecurityContext sc;
   private EJBAuthorizationHelper eah;
   private RoleGroup methodRoleGroup;
   
   protected void setUp() throws Exception
   {
      sc = new JBossSecurityContext("test");
      eah = new EJBAuthorizationHelper();
      eah.setSecurityContext(sc);
      eah.setPolicyRegistration(new JBossPolicyRegistration());
      methodRoleGroup = SecurityTestUtil.getRoleGroup(new String[]{"roleA", "roleC"});
      
      ApplicationPolicy ap = SecurityTestUtil.getApplicationPolicy("test", null);
      SecurityTestUtil.setUpRegularConfiguration(ap);
   }
   
   public void testValidAuthorization() throws Exception
   {
      Principal ejbPrincipal = new SimplePrincipal("AuthenticatedPrincipal");
      Subject callerSubject = new Subject();
      callerSubject.getPrincipals().add(ejbPrincipal); 

      RoleGroup roleGroup = SecurityTestUtil.getRoleGroup(new String[]{"roleA", "roleC"});
      
      //Add good roles to the context
      sc.getUtil().setRoles(roleGroup);
      
      boolean result = eah.authorize("TestEJB", 
            DummyClass.class.getMethod("someMethod", new Class[0]), 
            ejbPrincipal, 
            "void someMethod", 
            this.getClass().getProtectionDomain().getCodeSource(), 
            callerSubject, 
            null, 
            "ejb.jar", 
            methodRoleGroup);

      assertTrue("Authz", result);
   }
   
   public void testValidAuthorizationWithEJBResource() throws Exception
   {
      Principal ejbPrincipal = new SimplePrincipal("AuthenticatedPrincipal");
      Subject callerSubject = new Subject();
      callerSubject.getPrincipals().add(ejbPrincipal); 

      RoleGroup roleGroup = SecurityTestUtil.getRoleGroup(new String[]{"roleA", "roleC"});
      
      //Add good roles to the context
      sc.getUtil().setRoles(roleGroup);
      
      EJBResource ejbResource = new EJBResource( new HashMap<String, Object>());
      ejbResource.setEjbName( "TestEJB" );
      ejbResource.setEjbMethod( DummyClass.class.getMethod("someMethod", new Class[0]) );
      ejbResource.setPrincipal(ejbPrincipal);
      ejbResource.setEjbMethodInterface( "void someMethod" );
      ejbResource.setCodeSource(this.getClass().getProtectionDomain().getCodeSource() );
      ejbResource.setCallerSubject(callerSubject);
      ejbResource.setCallerRunAsIdentity( null );
      ejbResource.setPolicyContextID( "ejb.jar" );
      ejbResource.setEjbMethodRoles(methodRoleGroup);
      boolean result = eah.authorize( ejbResource );
      
      /*boolean result = eah.authorize("TestEJB", 
            DummyClass.class.getMethod("someMethod", new Class[0]), 
            ejbPrincipal, 
            "void someMethod", 
            this.getClass().getProtectionDomain().getCodeSource(), 
            callerSubject, 
            null, 
            "ejb.jar", 
            methodRoleGroup);*/

      assertTrue("Authz", result);
   }
   
   public void testInvalidAuthorization() throws Exception
   {
      Principal ejbPrincipal = new SimplePrincipal("AuthenticatedPrincipal");
      Subject callerSubject = new Subject();
      callerSubject.getPrincipals().add(ejbPrincipal); 

      RoleGroup roleGroup = SecurityTestUtil.getRoleGroup(new String[]{"villain"});
        
      //Add good roles to the context
      sc.getUtil().setRoles(roleGroup);
      
      boolean result = eah.authorize("TestEJB", 
            DummyClass.class.getMethod("someMethod", new Class[0]), 
            ejbPrincipal, 
            "void someMethod",  
            this.getClass().getProtectionDomain().getCodeSource(), 
            callerSubject, 
            null, 
            "ejb.jar", 
            methodRoleGroup);

      assertFalse("InvalidAuthz", result);
   }
   
   /**
    * Test that authorization fails when the subject has wrong role
    * @throws Exception
    */
   public void testInvalidAuthorizationWithEJBResource() throws Exception
   {
      Principal ejbPrincipal = new SimplePrincipal("AuthenticatedPrincipal");
      Subject callerSubject = new Subject();
      callerSubject.getPrincipals().add(ejbPrincipal); 

      RoleGroup roleGroup = SecurityTestUtil.getRoleGroup(new String[]{"villain"});
        
      //Add good roles to the context
      sc.getUtil().setRoles(roleGroup);
      
      EJBResource ejbResource = new EJBResource( new HashMap<String, Object>());
      ejbResource.setEjbName( "TestEJB" );
      ejbResource.setEjbMethod( DummyClass.class.getMethod("someMethod", new Class[0]) );
      ejbResource.setPrincipal(ejbPrincipal);
      ejbResource.setEjbMethodInterface( "void someMethod" );
      ejbResource.setCodeSource(this.getClass().getProtectionDomain().getCodeSource() );
      ejbResource.setCallerSubject(callerSubject);
      ejbResource.setCallerRunAsIdentity( null );
      ejbResource.setPolicyContextID( "ejb.jar" );
      ejbResource.setEjbMethodRoles(methodRoleGroup);
      
      boolean result = eah.authorize( ejbResource );
      
      /*boolean result = eah.authorize("TestEJB", 
            DummyClass.class.getMethod("someMethod", new Class[0]), 
            ejbPrincipal, 
            "void someMethod",  
            this.getClass().getProtectionDomain().getCodeSource(), 
            callerSubject, 
            null, 
            "ejb.jar", 
            methodRoleGroup);*/

      assertFalse("InvalidAuthz", result);
   }
   
   public void testRequiredParameters() throws Exception
   {
      Principal ejbPrincipal = new SimplePrincipal("AuthenticatedPrincipal");
      Subject callerSubject = new Subject();
      callerSubject.getPrincipals().add(ejbPrincipal); 

      RoleGroup roleGroup = SecurityTestUtil.getRoleGroup(new String[]{"villain"});
        
      //Add good roles to the context
      sc.getUtil().setRoles(roleGroup);
      
      try
      { 
         eah.authorize("TestEJB", 
               DummyClass.class.getMethod("someMethod", new Class[0]), 
               ejbPrincipal, 
               "void someMethod",  
               this.getClass().getProtectionDomain().getCodeSource(), 
               null, 
               null, 
               "ejb.jar", 
               methodRoleGroup);
         fail("Either subject or caller runas needs to be passed");
      }
      catch(IllegalArgumentException iae)
      {
         //pass
      }
   }
   
   public void testRequiredParametersWithEJBResource() throws Exception
   {
      Principal ejbPrincipal = new SimplePrincipal("AuthenticatedPrincipal");
      Subject callerSubject = new Subject();
      callerSubject.getPrincipals().add(ejbPrincipal); 

      RoleGroup roleGroup = SecurityTestUtil.getRoleGroup(new String[]{"villain"});
        
      CodeSource cs = this.getClass().getProtectionDomain().getCodeSource();
      //Add good roles to the context
      sc.getUtil().setRoles(roleGroup);
      
      EJBResource ejbResource = new EJBResource( new HashMap<String, Object>() );
      ejbResource.setEjbName( "TestEJB" );
      ejbResource.setEjbMethod( DummyClass.class.getMethod("someMethod", new Class[0]) );
      ejbResource.setPrincipal( ejbPrincipal );
      ejbResource.setEjbMethodInterface( "void someMethod" );
      ejbResource.setCodeSource( cs );
      ejbResource.setPolicyContextID( "ejb.jar" );
      ejbResource.setEjbMethodRoles( methodRoleGroup );
      
      //The following two conditions should throw an IllegalArgumentException
      ejbResource.setCallerRunAsIdentity( null );
      ejbResource.setCallerSubject( null );
      
      try
      { 
         eah.authorize( ejbResource );
         /*eah.authorize("TestEJB", 
               DummyClass.class.getMethod("someMethod", new Class[0]), 
               ejbPrincipal, 
               "void someMethod",  
               this.getClass().getProtectionDomain().getCodeSource(), 
               null, 
               null, 
               "ejb.jar", 
               methodRoleGroup);*/
         fail("Either subject or caller runas needs to be passed");
      }
      catch( MissingArgumentsException iae)
      {
         //pass
      }
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