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
package org.jboss.test.authentication.jaas;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.Principal;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.callback.PasswordValidationCallback;

import org.jboss.security.*;
import org.jboss.security.auth.callback.JASPICallbackHandler;
import org.jboss.security.identity.Identity;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.identity.extensions.CredentialIdentity;
import org.jboss.security.identity.plugins.SimpleRole;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * SECURITY-508: JASPI callback handler
 * @author Anil.Saldhana@redhat.com
 * @since May 12, 2010
 */
public class JASPICallbackHandlerUnitTestCase
{
   private Subject subject = new Subject();
   
   private Principal principal = new SimplePrincipal( "somePrincipal" );
   
   private Object cred = new char[] { 't', 'e' };
   
   @BeforeClass
   public static void setup() throws Exception
   { 
      SecurityContext sc = SecurityContextFactory.createSecurityContext( "test" );  
      SecurityContextAssociation.setSecurityContext(sc);
   }
   
   @AfterClass
   public static void tearDown()
   {
      SecurityContextAssociation.setSecurityContext(null);
   }

   @After
   public void clearSubjectInfo()
   {
      SecurityContext context = SecurityContextAssociation.getSecurityContext();
      context.getUtil().createSubjectInfo(null, null, null);
   }


   @Test
   public void testGroupPrincipalCallback() throws Exception
   {   
      JASPICallbackHandler cbh = new JASPICallbackHandler();
       
      GroupPrincipalCallback gpc = new GroupPrincipalCallback( subject, new String[] { "role1", "role2" } );
      
      cbh.handle( new Callback[] { gpc } ); 
      
      SecurityContext currentSC = SecurityContextAssociation.getSecurityContext();
      
      assertNotNull( "subject is not null" , gpc.getSubject() ); 
      assertEquals( subject, currentSC.getUtil().getSubject() );
      
      RoleGroup roles = currentSC.getUtil().getRoles();
      
      assertEquals( 2, roles.getRoles().size() );
      assertTrue( roles.containsRole( new SimpleRole( "role1" )));
      assertTrue( roles.containsRole( new SimpleRole( "role2" )));
   } 
   
   @Test
   public void testCallerPrincipalCallback() throws Exception
   {   
      JASPICallbackHandler cbh = new JASPICallbackHandler();
       
      CallerPrincipalCallback cpc = new CallerPrincipalCallback( subject, principal );
      
      cbh.handle( new Callback[] { cpc } ); 
      
      SecurityContext currentSC = SecurityContextAssociation.getSecurityContext();
      
      assertNotNull( "subject is not null" , cpc.getSubject() ); 
      assertEquals( subject, currentSC.getUtil().getSubject() ); 
      
      Set<Identity> identities = currentSC.getUtil().getIdentities( CredentialIdentity.class );
      assertEquals( 1, identities.size() ); 
      assertEquals( principal , currentSC.getUtil().getUserPrincipal() );
   }
   
   @Test
   public void testPasswordValidationCallback() throws Exception
   {   
      JASPICallbackHandler cbh = new JASPICallbackHandler();
       
      PasswordValidationCallback pvc = new PasswordValidationCallback( subject, principal.getName(), (char[]) cred );
      
      cbh.handle( new Callback[] { pvc } ); 
      
      SecurityContext currentSC = SecurityContextAssociation.getSecurityContext();
      
      assertNotNull( "subject is not null" , pvc.getSubject() ); 
      assertEquals( subject, currentSC.getUtil().getSubject() ); 
      
      assertEquals( principal, currentSC.getUtil().getUserPrincipal() );  
      assertEquals( cred, currentSC.getUtil().getCredential());
   }
}