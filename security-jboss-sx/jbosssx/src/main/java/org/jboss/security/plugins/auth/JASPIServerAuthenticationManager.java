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
package org.jboss.security.plugins.auth;

import java.util.HashMap;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.AuthConfigProvider;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.jacc.PolicyContext;

import org.jboss.security.AuthenticationManager;
import org.jboss.security.ServerAuthenticationManager;

/**
 * @author Anil.Saldhana@redhat.com
 */
public class JASPIServerAuthenticationManager 
extends JaasSecurityManagerBase implements ServerAuthenticationManager
{   
   public JASPIServerAuthenticationManager()
   {
      super(); 
   }

   public JASPIServerAuthenticationManager(String securityDomain, CallbackHandler handler)
   {
      super(securityDomain, handler); 
   }

   /**
    * @see AuthenticationManager#isValid(MessageInfo, Subject, String, CallbackHandler)
    */
   @SuppressWarnings("unchecked")
   public boolean isValid(MessageInfo requestMessage,Subject clientSubject, String layer,
         CallbackHandler handler)
   { 
      AuthStatus status = AuthStatus.FAILURE;
      
      try
      {
         String contextID = PolicyContext.getContextID();
         AuthConfigFactory factory = AuthConfigFactory.getFactory();
         AuthConfigProvider provider = factory.getConfigProvider(layer,contextID,null); 
         if(provider == null)
            throw new IllegalStateException("Provider is null for "+ layer + " for "+ contextID);
         
         ServerAuthConfig serverConfig = provider.getServerAuthConfig(layer,contextID,handler);  
         ServerAuthContext sctx = serverConfig.getAuthContext(contextID, 
               new Subject(), new HashMap());
         if(clientSubject == null)
            clientSubject = new Subject();
         Subject serviceSubject = new Subject();
         status = sctx.validateRequest(requestMessage, clientSubject, serviceSubject); 
         //TODO: Add caching
      }
      catch(AuthException ae)
      {
         if(trace)
            log.trace("AuthException:",ae);
      } 
      return AuthStatus.SUCCESS == status ;
   }
   
}