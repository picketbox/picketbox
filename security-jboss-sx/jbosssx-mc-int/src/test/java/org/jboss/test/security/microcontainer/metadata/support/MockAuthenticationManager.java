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
package org.jboss.test.security.microcontainer.metadata.support;

import java.security.Principal;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.MessageInfo;

import org.jboss.security.AuthenticationManager;

/**
 * <p>
 * A mock {@code AuthenticationManager} implementation used in the tests.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class MockAuthenticationManager implements AuthenticationManager
{
   private final String domainName;

   /**
    * <p>
    * Creates an instance of {@code MockAuthenticationManager} with the specified security domain name.
    * </p>
    * 
    * @param domainName a {@code String} representing the name of the security domain.
    */
   public MockAuthenticationManager(String domainName)
   {
      this.domainName = domainName;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.AuthenticationManager#getActiveSubject()
    */
   @Deprecated
   public Subject getActiveSubject()
   {
      return null;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.AuthenticationManager#getTargetPrincipal(java.security.Principal, java.util.Map)
    */
   public Principal getTargetPrincipal(Principal principal, Map<String, Object> options)
   {
      return null;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.AuthenticationManager#isValid(java.security.Principal, java.lang.Object)
    */
   public boolean isValid(Principal principal, Object credentials)
   {
      return false;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.AuthenticationManager#isValid(java.security.Principal, java.lang.Object,
    *      javax.security.auth.Subject)
    */
   public boolean isValid(Principal principal, Object credentials, Subject subject)
   {
      return false;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.AuthenticationManager#isValid(javax.security.auth.message.MessageInfo,
    *      javax.security.auth.Subject, java.lang.String)
    */
   public boolean isValid(MessageInfo info, Subject subject, String layer)
   {
      return false;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.AuthenticationManager#isValid(javax.security.auth.message.MessageInfo,
    *      javax.security.auth.Subject, java.lang.String, javax.security.auth.callback.CallbackHandler)
    */
   public boolean isValid(MessageInfo info, Subject subject, String layer, CallbackHandler handler)
   {
      return false;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.BaseSecurityManager#getSecurityDomain()
    */
   public String getSecurityDomain()
   {
      return domainName;
   }

}
