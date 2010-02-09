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

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.security.auth.Subject;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import junit.framework.TestCase;

import org.jboss.security.SecurityContext;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.plugins.JBossPolicyRegistration;
import org.jboss.security.plugins.JBossSecurityContext;
import org.jboss.security.plugins.javaee.WebAuthorizationHelper;
import org.jboss.test.util.SecurityTestUtil;
import org.jboss.test.util.TestHttpServletRequest;
 
/**
 *  Unit Tests for the Web Authorization Helper
 *  @author Anil.Saldhana@redhat.com
 *  @since  Apr 18, 2008 
 *  @version $Revision$
 */
public class WebAuthorizationHelperUnitTestCase extends TestCase
{
   private SecurityContext sc;
   private WebAuthorizationHelper wah; 
    
   protected void setUp() throws Exception
   {
      sc = new JBossSecurityContext("test");
      wah = new WebAuthorizationHelper();
      wah.setSecurityContext(sc);
      wah.setPolicyRegistration(new JBossPolicyRegistration()); 
        
      Map<String,Object> moduleOptions = SecurityTestUtil.getWebDelegateOptions();
      ApplicationPolicy ap = SecurityTestUtil.getApplicationPolicy("test", moduleOptions);
      SecurityTestUtil.setUpRegularConfiguration(ap); 
       
      //Mainly for the TestWebAuthorizationModuleDelegate
      System.setProperty("/someuri", "roleA");
   }
   
   public void testValidWebAuthorization() throws Exception
   {
      //Create a ContextMap
      Map<String,Object> contextMap = new HashMap<String,Object>();  
      
      HttpServletRequest request = new TestHttpServletRequest(new SimplePrincipal("someprincipal"),
            "/someuri", "GET");
      
      RoleGroup roleGroup = SecurityTestUtil.getRoleGroup(new String[]{"roleA", "roleC"});
      
      //Add good roles to the context
      sc.getUtil().setRoles(roleGroup);
      
      boolean result = wah.checkResourcePermission(contextMap, 
            request, 
            getDummyResponse(), 
            new Subject(), 
            "web.jar", 
            "/someuri");
      
      assertTrue("Web Authz", result);
   }
   
   public void testInvalidWebAuthorization() throws Exception
   {
    //Create a ContextMap
      Map<String,Object> contextMap = new HashMap<String,Object>();  
      
      HttpServletRequest request = new TestHttpServletRequest(new SimplePrincipal("someprincipal"),
            "/someuri", "GET");
      
      RoleGroup roleGroup = SecurityTestUtil.getRoleGroup(new String[]{"Villain"});
      
      //Add good roles to the context
      sc.getUtil().setRoles(roleGroup);
      
      boolean result = wah.checkResourcePermission(contextMap, 
            request, 
            getDummyResponse(), 
            new Subject(), 
            "web.jar", 
            "/someuri");
      
      assertFalse("Invalid Web Authz", result); 
   }
   
   private ServletResponse getDummyResponse()
   {
      return new ServletResponse()
      {
         public void flushBuffer() throws IOException
         {
         }

         public int getBufferSize()
         {
            return 0;
         }

         public String getCharacterEncoding()
         {
            return null;
         }

         public String getContentType()
         {
            return null;
         }

         public Locale getLocale()
         {
            return null;
         }

         public ServletOutputStream getOutputStream() throws IOException
         {
            return null;
         }

         public PrintWriter getWriter() throws IOException
         {
            return null;
         }

         public boolean isCommitted()
         {
            return false;
         }

         public void reset()
         {
         }

         public void resetBuffer()
         {
         }

         public void setBufferSize(int arg0)
         {
         }

         public void setCharacterEncoding(String arg0)
         {
         }

         public void setContentLength(int arg0)
         {
         }

         public void setContentType(String arg0)
         {
         }

         public void setLocale(Locale arg0)
         {
         }};
   }
}