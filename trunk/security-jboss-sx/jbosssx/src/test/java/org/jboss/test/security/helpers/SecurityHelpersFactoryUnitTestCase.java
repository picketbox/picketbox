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

import junit.framework.TestCase;

import org.jboss.security.SecurityContext;
import org.jboss.security.javaee.EJBAuthenticationHelper;
import org.jboss.security.javaee.SecurityHelperFactory;
import org.jboss.security.plugins.JBossSecurityContext;
import org.jboss.security.plugins.javaee.EJBAuthorizationHelper;
import org.jboss.security.plugins.javaee.WebAuthorizationHelper;
 
/**
 *  Unit tests for the security helper factory
 *  @author Anil.Saldhana@redhat.com
 *  @since  Apr 18, 2008 
 *  @version $Revision$
 */
public class SecurityHelpersFactoryUnitTestCase extends TestCase
{
   private SecurityContext sc = new JBossSecurityContext("test");
    
   public void testEJBAuthenticationHelper()
   {
     EJBAuthenticationHelper eah = SecurityHelperFactory.getEJBAuthenticationHelper(sc);     
     assertNotNull("auth helper",eah);
   } 
   
   public void testEJBAuthorizationHelper() throws Exception
   {
     Object obj = SecurityHelperFactory.getEJBAuthorizationHelper(sc);
     assertNotNull("ejb authz", obj);
     assertTrue(obj instanceof EJBAuthorizationHelper);
   }
   
   public void testWebAuthorizationHelper() throws Exception
   {
     Object obj = SecurityHelperFactory.getWebAuthorizationHelper(sc);
     assertNotNull("web authz", obj);
     assertTrue(obj instanceof WebAuthorizationHelper);
   }
}