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
package org.jboss.test.authorization.web;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;

import junit.framework.TestCase;

import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.callback.AppCallbackHandler;
import org.jboss.security.authorization.AuthorizationContext;
import org.jboss.security.authorization.resources.WebResource;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.plugins.authorization.JBossAuthorizationContext;
import org.jboss.test.util.SecurityTestUtil;
import org.jboss.test.util.TestHttpServletRequest;

/**
 *  Unit Test the Web Authorization Modules
 *  @author Anil.Saldhana@redhat.com
 *  @since  Nov 26, 2007 
 *  @version $Revision$
 */
public class WebAuthorizationUnitTestCase extends TestCase
{   
   private WebResource webResource;
   
   protected void setUp() throws Exception
   {
      Map<String,Object> moduleOptions = SecurityTestUtil.getWebDelegateOptions();
      ApplicationPolicy ap = SecurityTestUtil.getApplicationPolicy("test", moduleOptions);
      SecurityTestUtil.setUpRegularConfiguration(ap); 
      
      HttpServletRequest hsr = new TestHttpServletRequest(new SimplePrincipal("someprincipal"),
            "/someuri", "GET");
      //Create a ContextMap
      Map<String,Object> cmap = new HashMap<String,Object>();  
      webResource = new WebResource(cmap);
      webResource.setServletRequest(hsr);
      webResource.setCanonicalRequestURI("/someuri");
 
      //Mainly for the TestWebAuthorizationModuleDelegate
      System.setProperty("/someuri", "roleA");
   }
   
   public void testRegularWebAccess() throws Exception
   {
      AuthorizationContext ac = new JBossAuthorizationContext("test",
            new Subject(), new AppCallbackHandler("a","b".toCharArray()));
      int result = ac.authorize(webResource, new Subject(), 
            SecurityTestUtil.getRoleGroup(new String[]{"roleA"}));
      assertEquals(AuthorizationContext.PERMIT, result); 
   }
   
   public void testInvalidWebAccess() throws Exception
   {
      AuthorizationContext ac = new JBossAuthorizationContext("test",
            new Subject(), new AppCallbackHandler("a","b".toCharArray()));
      int result = ac.authorize(webResource, new Subject(), 
            SecurityTestUtil.getRoleGroup(new String[]{"roleA"}));
      assertEquals(AuthorizationContext.PERMIT, result); 
   } 
}