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
import java.security.PrivilegedActionException;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

import org.jboss.logging.Logger;
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
import org.picketbox.exceptions.PicketBoxProcessingException;
import org.picketbox.factories.SecurityFactory;

/**
 * <p> Process the security annotations on a POJO.</p>
 * <p>
 * Additionally, there are various useful methods such as {@code #getCallerPrincipal()} to
 * get the authenticated principal, {@code #getCallerSubject()} to get the authenticated
 * subject and {@code #getCallerRoles()} to get the roles for the authenticated subject.
 * </p>
 * @since Feb 16, 2010
 */
public class PicketBoxProcessor
{
   private static Logger log = Logger.getLogger(PicketBoxProcessor.class);
   
   private Principal principal = null;
   private Object credential = null;
   
   public PicketBoxProcessor()
   {   
   } 
   
   /**
    * <p>
    * Set the user name/ Credential
    * </p>
    * 
    * <p>
    * In the case of X509 certificates, they can be passed
    * as the Credential into this method.
    * </p>
    * 
    * @param userName
    * @param credential
    */
   public void setSecurityInfo(String userName, Object credential)
   {
      this.principal = new SimplePrincipal(userName);
      this.credential = credential; 
   }
   
   /**
    * Get the authenticated principal
    * @return 
    * @throws PicketBoxProcessingException 
    */
   public Principal getCallerPrincipal() throws PicketBoxProcessingException
   {
      Principal principal = null;
      
      SecurityContext securityContext = null;
      try
      {
         securityContext = SecurityActions.getSecurityContext();
      }
      catch (PrivilegedActionException pae)
      {
         throw new PicketBoxProcessingException(pae.getCause());
      }
      if(securityContext != null)
         principal = securityContext.getUtil().getUserPrincipal(); 
      return principal;
   }
   
   /**
    * Get the caller roles
    * @return 
    * @throws PicketBoxProcessingException 
    */
   public RoleGroup getCallerRoles() throws PicketBoxProcessingException
   {
      RoleGroup roleGroup = null;
      
      SecurityContext securityContext = null;
      try
      {
         securityContext = SecurityActions.getSecurityContext();
      }
      catch (PrivilegedActionException pae)
      {
         throw new PicketBoxProcessingException(pae.getCause());
      }
      if(securityContext != null)
         roleGroup = securityContext.getUtil().getRoles(); 
      return roleGroup;
   }
   
   /**
    * Get the caller subject
    * @return 
    * @throws PicketBoxProcessingException 
    */
   public Subject getCallerSubject() throws PicketBoxProcessingException
   {
      Subject subject = new Subject();
      SecurityContext securityContext = null;
      try
      {
         securityContext = SecurityActions.getSecurityContext();
      }
      catch (PrivilegedActionException pae)
      {
         throw new PicketBoxProcessingException(pae.getCause());
      }
      if(securityContext != null)
         subject = securityContext.getUtil().getSubject();
      return subject;
   }
   
   /**
    * Process the POJO for security annotations
    * @param pojo
    * @throws PicketBoxProcessingException 
    * @throws LoginException
    */
   public void process(Object pojo) throws LoginException, PicketBoxProcessingException
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
         
         //We try to get the roles of the current authenticated subject. This internally will also
         //apply the role mapping logic if it is configured at the security domain level
         RoleGroup roles = authzMgr.getSubjectRoles(subject, cbh); 
         if(roles == null)
            throw new PicketBoxProcessingException("Roles from subject is null");  
      }
      catch(PrivilegedActionException pae)
      {
         if(log.isTraceEnabled())
            log.trace("Exception in processing:",pae);
         throw new PicketBoxProcessingException(pae.getCause());
      }
      finally
      {
         SecurityFactory.release();
      } 
   }
}