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
package org.jboss.test.authentication.jaspi;


import java.io.IOException;
import java.net.URL;
import java.security.Principal;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.Configuration;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestSuite;

import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.auth.login.XMLLoginConfigImpl;
import org.jboss.security.auth.message.GenericMessageInfo;
import org.jboss.security.config.parser.StaxBasedConfigParser;
import org.jboss.security.plugins.JBossSecurityContext;
import org.jboss.security.plugins.auth.JASPIServerAuthenticationManager;
import org.jboss.test.JBossTestCase;
import org.jboss.test.JBossTestSetup;


/**
 * Test the JASPI options (required, requisite, sufficient, optional) behavior
 * 
 * @author Anil.Saldhana@redhat.com
 * @since Jul 16, 2007
 * @version $Revision$
 */
public class AuthContext2UnitTestCase extends JBossTestCase
{ 
   public AuthContext2UnitTestCase(String name)
   {
      super(name); 
   }

   public static Test suite() throws Exception
   {
      TestSuite suite = new TestSuite();
      suite.addTest(new TestSuite(AuthContext2UnitTestCase.class));
      // Create an initializer for the test suite
      TestSetup wrapper = new JBossTestSetup(suite)
      { 
         protected void setUp() throws Exception
         {
            super.setUp(); 
            ClassLoader tcl = Thread.currentThread().getContextClassLoader();
            URL url = tcl.getResource("config/jaspi-config-options.xml");
            if(url == null)
               throw new IllegalStateException("config url is null");
            Configuration.setConfiguration(XMLLoginConfigImpl.getInstance());
            loadXMLConfig(url);
         }
         protected void tearDown() throws Exception
         {  
            super.tearDown(); 
         }
      };
      return wrapper; 
   } 


   /**
    * Test the AuthorizationModule required behavior
    */
   public void testRequiredOptionBehavior() throws Exception
   {   
      boolean result = getResult("required-permit-policy");
      assertTrue("PERMIT?", true == result);
      result = getResult("required-deny-policy");
      assertTrue("DENY?", false == result);
   }

   /**
    * Test the AuthorizationModule requisite behavior
    */
   public void testRequisiteOptionBehavior() throws Exception
   {   
      boolean result = getResult("requisite-permit-policy");
      assertTrue("PERMIT?", true == result);
      result = getResult("requisite-deny-policy");
      assertTrue("DENY?", false == result);
   }


   /**
    * Test the AuthorizationModule sufficient behavior
    */
   public void testSufficientOptionBehavior() throws Exception
   {   
      boolean result = getResult("sufficient-permit-policy");
      assertTrue("PERMIT?", true == result);
      result = getResult("sufficient-deny-policy");
      assertTrue("DENY?", false == result);
   }


   /**
    * Test the AuthorizationModule optional behavior
    */
   public void testOptionalOptionBehavior() throws Exception
   {   
      boolean result = getResult("optional-permit-policy");
      assertTrue("PERMIT?", true == result);
      result = getResult("optional-deny-policy");
      assertTrue("DENY?", false == result);
   }

   /**
    * Test the AuthorizationModules combination behavior
    */
   public void testCombinationBehavior() throws Exception
   {   
      boolean result = getResult("required-deny-sufficient-permit-policy");
      assertTrue("DENY?", false == result); 
      result = getResult("required-permit-sufficient-deny-policy");
      assertTrue("PERMIT?", true == result); 
      result = getResult("required-permit-required-deny-policy");
      assertTrue("DENY?", false == result);
      result = getResult("required-permit-required-permit-policy");
      assertTrue("PERMIT?", true == result);
      result = getResult("required-permit-required-permit-sufficient-deny-policy");
      assertTrue("PERMIT?", true == result);
      result = getResult("required-permit-required-permit-requisite-deny-policy");
      assertTrue("PERMIT?", true == result);
      result = getResult("required-permit-required-permit-optional-deny-policy");
      assertTrue("PERMIT?", true == result);
      result = getResult("required-permit-required-deny-requisite-permit-policy");
      assertTrue("DENY?", false == result); 
      result = getResult("requisite-permit-requisite-permit-sufficient-deny-policy");
      assertTrue("PERMIT?", true == result);

      result = getResult("sufficient-permit-required-deny-policy");
      assertTrue("PERMIT?", true == result);
      result = getResult("sufficient-permit-sufficient-deny-policy");
      assertTrue("PERMIT?", true == result);
      result = getResult("optional-deny-sufficient-permit-required-deny-policy");
      assertTrue("PERMIT?", true == result);

      result = getResult("sufficient-deny-optional-deny-policy");
      assertTrue("DENY?", false == result);
   }

   private boolean getResult(String policyName) throws Exception
   {  
      SecurityContext securityContext = new JBossSecurityContext(policyName);
      SecurityContextAssociation.setSecurityContext(securityContext);
      
      CallbackHandler handler = new TestCallbackHandler();
      JASPIServerAuthenticationManager aContext = new JASPIServerAuthenticationManager(policyName,
            handler);  
      GenericMessageInfo requestMessage = new GenericMessageInfo(new Object(), new Object());
      return  aContext.isValid(requestMessage, new Subject(), "HttpServlet", 
            handler); 
   }

   /**
    * Use JBossXB to parse the security config file
    * @param loginConfigURL
    * @throws Exception
    */
   private static void loadXMLConfig(URL loginConfigURL)
   throws Exception 
   {
      if(loginConfigURL == null)
         throw new IllegalArgumentException("loginConfigURL is null");
      new StaxBasedConfigParser().parse2(loginConfigURL.openStream());
   } 

   /**
    * Dummy CallbackHandler
    */
   private static class TestCallbackHandler implements CallbackHandler
   { 
      @SuppressWarnings("unused")
      public void setSecurityInfo(Principal principal, Object credential)
      {
      }
      
      public void handle(Callback[] arg0) throws IOException, UnsupportedCallbackException
      {
      } 
   } 
}