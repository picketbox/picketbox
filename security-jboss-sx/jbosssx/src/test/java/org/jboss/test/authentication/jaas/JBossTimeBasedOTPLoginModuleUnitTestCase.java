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

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.acl.Group;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.security.jacc.PolicyContextHandler;

import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.callback.JBossCallbackHandler;
import org.jboss.security.auth.spi.otp.JBossTimeBasedOTPLoginModule;
import org.jboss.security.otp.TimeBasedOTP;
import org.jboss.test.util.TestHttpServletRequest;
import org.junit.Test;

/**
 * Unit Test the {@code JBossTimeBasedOTPLoginModule}
 * @author Anil.Saldhana@redhat.com
 * @since Sep 21, 2010
 */
public class JBossTimeBasedOTPLoginModuleUnitTestCase
{
   static String seed = "3132333435363738393031323334353637383930";

   static final String WEB_REQUEST_KEY = "javax.servlet.http.HttpServletRequest";
   
   @Test
   public void testTOTP() throws Exception
   {
      try
      {
         String totp =  TimeBasedOTP.generateTOTP( seed, 6 ) ; 
         PolicyContext.registerHandler( WEB_REQUEST_KEY, getHandler(totp), true );
      }
      catch (GeneralSecurityException e)
      {
         throw new RuntimeException( e );
      } 
      
      Principal principal = new SimplePrincipal( "anil" );
      
      Subject subject = new Subject();
      CallbackHandler callbackHandler = new JBossCallbackHandler(principal, seed );
      Map<String,Object> sharedState = new HashMap<String,Object>();
      Map<String, Object> options = new HashMap<String,Object>();
      
      JBossTimeBasedOTPLoginModule jtp = new JBossTimeBasedOTPLoginModule();
      jtp.initialize(subject, callbackHandler, sharedState, options); 
      jtp.login();
   }  
   
   @Test
   public void testInvalidAuth() throws Exception
   {
      PolicyContext.registerHandler( WEB_REQUEST_KEY, getHandler( "ArbitraryDummy" ), true ); 
      
      Principal principal = new SimplePrincipal( "anil" );
      
      Subject subject = new Subject();
      CallbackHandler callbackHandler = new JBossCallbackHandler(principal, seed );
      Map<String,Object> sharedState = new HashMap<String,Object>();
      Map<String, Object> options = new HashMap<String,Object>();
      
      JBossTimeBasedOTPLoginModule jtp = new JBossTimeBasedOTPLoginModule();
      jtp.initialize(subject, callbackHandler, sharedState, options); 
      try
      {
         jtp.login();
         fail( "Should have failed auth" );
      }
      catch( LoginException le )
      {
         //pass
      }
   }
   
   @Test
   public void testTOTPWithAdditionalRoles() throws Exception
   {
      try
      {
         String totp =  TimeBasedOTP.generateTOTP( seed, 6 ) ; 
         PolicyContext.registerHandler( WEB_REQUEST_KEY, getHandler(totp), true );
      }
      catch (GeneralSecurityException e)
      {
         throw new RuntimeException( e );
      } 
      
      Principal principal = new SimplePrincipal( "anil" );
      
      Subject subject = new Subject();
      CallbackHandler callbackHandler = new JBossCallbackHandler(principal, seed );
      Map<String,Object> sharedState = new HashMap<String,Object>();
      Map<String, Object> options = new HashMap<String,Object>();
      options.put( "additionalRoles", "RoleA,RoleB" );
      
      //Add in a subject group principal
      Group group = new SimpleGroup( "Roles" );
      subject.getPrincipals().add( group );
      
      JBossTimeBasedOTPLoginModule jtp = new JBossTimeBasedOTPLoginModule();
      jtp.initialize(subject, callbackHandler, sharedState, options); 
      jtp.login();
      
      Set<Group> groups = subject.getPrincipals( Group.class );
      assertTrue( "set has 1 group", groups.size() == 1 );
      Group retrievedGroup = groups.iterator().next();
      assertTrue( retrievedGroup.isMember( new SimplePrincipal( "RoleA" )));
      assertTrue( retrievedGroup.isMember( new SimplePrincipal( "RoleB" )));
   }  
   
   /**
    * Create a JACC Policy Context Handler that takes in a totp string
    * and returns a {@code HttpServletRequest} with the totp as parameter
    * @param totp
    * @return
    */
   private static PolicyContextHandler getHandler( final String totp )
   {
      return new PolicyContextHandler()
      {
         public Object getContext(String key, Object data) throws PolicyContextException
         { 
            if( WEB_REQUEST_KEY.equals( key ))
            {  
               TestHttpServletRequest tsr = new TestHttpServletRequest();
               tsr.setParameter( "totp", totp );
               
               return tsr; 
            } 
            return null;
         }

         public String[] getKeys() throws PolicyContextException
         { 
            return null;
         }

         public boolean supports(String key) throws PolicyContextException
         {
            if( WEB_REQUEST_KEY.equals( key ))
               return true;
            
            return false;
         }
      }; 
   } 
}