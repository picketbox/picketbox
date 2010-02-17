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
package org.picketbox.plugins;

import java.security.Principal;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

import org.jboss.security.AuthenticationManager;
import org.jboss.security.AuthorizationManager;
import org.jboss.security.SecurityConstants;
import org.jboss.security.SecurityContext;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.annotation.SecurityConfig;
import org.jboss.security.annotation.SecurityDomain;
import org.jboss.security.callbacks.SecurityContextCallbackHandler;
import org.jboss.security.identity.RoleGroup;
import org.picketbox.config.PicketBoxConfiguration;
import org.picketbox.factories.SecurityFactory;

/**
 * Process the security annotations on a POJO
 * @since Feb 16, 2010
 */
public class PicketBoxProcessor
{
   Principal principal = null;
   Object credential = null;
   
   public PicketBoxProcessor()
   {   
   } 
   
   public void setSecurityInfo(String username, Object credential)
   {
      this.principal = new SimplePrincipal(username);
      this.credential = credential; 
   }
   
   public Principal getCallerPrincipal() throws Exception
   {
      Principal principal = null;
      
      SecurityContext securityContext =  SecurityActions.getSecurityContext();
      if(securityContext != null)
         principal = securityContext.getUtil().getUserPrincipal(); 
      return principal;
   }
   
   public RoleGroup getCallerRoles() throws Exception
   {
      RoleGroup roleGroup = null;
      
      SecurityContext securityContext =  SecurityActions.getSecurityContext();
      if(securityContext != null)
         roleGroup = securityContext.getUtil().getRoles(); 
      return roleGroup;
   }
   
   public Subject getCallerSubject() throws Exception
   {
      Subject subject = new Subject();
      SecurityContext securityContext =  SecurityActions.getSecurityContext();
      if(securityContext != null)
         subject = securityContext.getUtil().getSubject();
      return subject;
   }
   
   public void process(Object pojo) throws Exception
   {
      String securityDomain = SecurityConstants.DEFAULT_APPLICATION_POLICY;
      
      Class<?> objectClass = pojo.getClass();
      
      SecurityDomain securityDomainAnnotation = objectClass.getAnnotation(SecurityDomain.class);
      if(securityDomainAnnotation != null)
         securityDomain = securityDomainAnnotation.value();

      SecurityFactory.prepare();
      try
      {
         SecurityConfig securityConfig = objectClass.getAnnotation(SecurityConfig.class);
         if(securityConfig == null)
            throw new RuntimeException("@SecurityConfig is missing");

         PicketBoxConfiguration idtrustConfig = new PicketBoxConfiguration();
         idtrustConfig.load(securityConfig.fileName());
         
         SecurityContext securityContext = SecurityActions.createSecurityContext(securityDomain);
         SecurityActions.setSecurityContext(securityContext);
         
         AuthenticationManager authMgr = SecurityFactory.getAuthenticationManager(securityDomain);
         
         Subject subject = new Subject();
         boolean valid = authMgr.isValid(principal, credential, subject);
         if(!valid)
            throw new LoginException("Invalid");
         
         SecurityActions.register(securityContext, principal, credential, subject); 

         AuthorizationManager authzMgr = SecurityFactory.getAuthorizationManager(securityDomain);
         SecurityContextCallbackHandler cbh = new SecurityContextCallbackHandler(securityContext);
         
         RoleGroup roles = authzMgr.getSubjectRoles(subject, cbh); 
         if(roles == null)
            throw new RuntimeException("Roles from subject is null");  
      }
      finally
      {
         SecurityFactory.release();
      } 
   }
}