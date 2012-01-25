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

import java.net.URL;
import java.util.HashMap;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.AuthConfigFactory;

import org.jboss.security.SecurityConstants;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.auth.callback.AppCallbackHandler;
import org.jboss.security.auth.callback.JBossCallbackHandler;
import org.jboss.security.auth.login.XMLLoginConfigImpl;
import org.jboss.security.auth.message.GenericMessageInfo;
import org.jboss.security.auth.message.config.JBossAuthConfigProvider;
import org.jboss.security.plugins.JBossSecurityContext;
import org.jboss.security.plugins.auth.JASPIServerAuthenticationManager;
import org.jboss.test.SecurityActions;

import junit.framework.TestCase;

/**
 * Unit Test the JASPIServerAuthenticationManager
 * @author Anil.Saldhana@redhat.com
 */
public class JASPIServerAuthenticationManagerUnitTestCase extends TestCase
{
   AuthConfigFactory factory = null;

   String layer = SecurityConstants.SERVLET_LAYER;

   String appId = "localhost /petstore";

   String configFile = "config/jaspi-config.xml";

   JASPIServerAuthenticationManager jaspiManager;
   
   @SuppressWarnings("unchecked")
   protected void setUp() throws Exception
   {
      factory = AuthConfigFactory.getFactory();
      factory.registerConfigProvider(new JBossAuthConfigProvider(new HashMap(), null), layer, appId,
            "Test Config Provider");

      jaspiManager = new JASPIServerAuthenticationManager("conf-jaspi", new JBossCallbackHandler());
//      SecurityContext jsc = new JBossSecurityContext("conf-jaspi");
//      SecurityContextAssociation.setSecurityContext(jsc);

      XMLLoginConfigImpl xli = XMLLoginConfigImpl.getInstance();
      SecurityActions.setJAASConfiguration(xli);

      URL configURL = Thread.currentThread().getContextClassLoader().getResource(configFile);
      assertNotNull("Config URL", configURL);

      xli.setConfigURL(configURL);
      xli.loadConfig();
   }

   public void testIsValid()
   {
      CallbackHandler cbh = new AppCallbackHandler("anil", "anilpwd".toCharArray());
      MessageInfo messageInfo = new GenericMessageInfo(new Object(), new Object());
      boolean valid = jaspiManager.isValid(messageInfo, new Subject(), layer, cbh);
      assertTrue(valid);
   }

   public void testIsInValid()
   {
      CallbackHandler cbh = new AppCallbackHandler("anil", "dead".toCharArray());
      MessageInfo messageInfo = new GenericMessageInfo(new Object(), new Object());
      boolean valid = jaspiManager.isValid(messageInfo, new Subject(), layer, cbh);
      assertFalse(valid);
   }
}