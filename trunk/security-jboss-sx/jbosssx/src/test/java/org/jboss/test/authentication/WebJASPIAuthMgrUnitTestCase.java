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
package org.jboss.test.authentication;

import java.net.URL;

import javax.security.auth.Subject;
import javax.security.auth.message.MessageInfo;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.ServerAuthenticationManager;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.callback.AppCallbackHandler;
import org.jboss.security.auth.callback.JBossCallbackHandler;
import org.jboss.security.auth.login.XMLLoginConfigImpl;
import org.jboss.security.auth.message.GenericMessageInfo;
import org.jboss.security.plugins.JBossSecurityContext;
import org.jboss.security.plugins.auth.JASPIServerAuthenticationManager;
import org.jboss.test.SecurityActions;
import org.jboss.test.util.TestHttpServletRequest;

/**
 * Unit tests for the JBossAuthenticationManager with JASPI
 * 
 * @author Anil.Saldhana@redhat.com
 * @since May 10, 2007
 * @version $Revision$
 */
public class WebJASPIAuthMgrUnitTestCase extends JBossAuthenticationManagerUnitTestCase
{
   String securityDomain = "web-jaspi";

   AppCallbackHandler acbh = new AppCallbackHandler();

   @Override
   protected void setUp() throws Exception
   {
      super.setUp();
      JBossSecurityContext jsc = new JBossSecurityContext(securityDomain);
      SecurityContextAssociation.setSecurityContext(jsc);
      establishSecurityConfiguration();
   }

   @Override
   public void testLogin() throws Exception
   {
      HttpServletRequest hsr = getHttpServletRequest("jduke", "theduke");
      MessageInfo mi = new GenericMessageInfo(hsr, (HttpServletResponse) null);
      ServerAuthenticationManager am = new JASPIServerAuthenticationManager(securityDomain, acbh);
      assertTrue(am.isValid(mi, (Subject)null, "HTTP", new JBossCallbackHandler()));
   }

   @Override
   public void testUnsuccessfulLogin() throws Exception
   {
      HttpServletRequest hsr = getHttpServletRequest("jduke", "BAD");
      MessageInfo mi = new GenericMessageInfo(hsr, (HttpServletResponse) null);
      ServerAuthenticationManager am = new JASPIServerAuthenticationManager(securityDomain, acbh);
      assertFalse(am.isValid(mi, (Subject)null, "HTTP", null));
   }

   private void establishSecurityConfiguration()
   {
      XMLLoginConfigImpl xli = XMLLoginConfigImpl.getInstance();
      SecurityActions.setJAASConfiguration(xli);
      URL configURL = Thread.currentThread().getContextClassLoader().getResource("config/jaspi-config.xml");
      assertNotNull("Config URL", configURL);
      xli.setConfigURL(configURL);
      xli.loadConfig();
   }

   @SuppressWarnings("unchecked")
   public HttpServletRequest getHttpServletRequest(String username, String pass)
   {
      HttpServletRequest hsr = new TestHttpServletRequest(new SimplePrincipal(username), pass, "GET");
      hsr.getParameterMap().put("j_username", username);
      hsr.getParameterMap().put("j_password", pass);
      return hsr;
   }
}