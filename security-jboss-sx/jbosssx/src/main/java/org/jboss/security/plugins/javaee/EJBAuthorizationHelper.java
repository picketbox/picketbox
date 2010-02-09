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
package org.jboss.security.plugins.javaee;

import java.lang.reflect.Method;
import java.security.CodeSource;
import java.security.Principal;
import java.util.HashMap;
import java.util.Set;

import javax.naming.InitialContext;
import javax.security.auth.Subject;

import org.jboss.logging.Logger;
import org.jboss.security.AuthorizationManager;
import org.jboss.security.RunAs;
import org.jboss.security.audit.AuditLevel;
import org.jboss.security.authorization.AuthorizationContext;
import org.jboss.security.authorization.PolicyRegistration;
import org.jboss.security.authorization.ResourceKeys;
import org.jboss.security.authorization.resources.EJBResource;
import org.jboss.security.callbacks.SecurityContextCallbackHandler;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.javaee.AbstractEJBAuthorizationHelper;
import org.jboss.security.javaee.SecurityRoleRef;


/**
 *  Default implementation of the EJBAuthorizationHelper
 *  @author Anil.Saldhana@redhat.com
 *  @since  Apr 18, 2008 
 *  @version $Revision$
 */
public class EJBAuthorizationHelper extends AbstractEJBAuthorizationHelper
{
   protected static Logger log = Logger.getLogger(EJBAuthorizationHelper.class);
   
   @Override
   public boolean authorize(
         String ejbName, 
         Method ejbMethod, 
         Principal ejbPrincipal, 
         String invocationInterfaceString,
         CodeSource ejbCS, 
         Subject callerSubject, 
         RunAs callerRunAs,  
         String contextID,
         RoleGroup methodRoles)
   {
      if(ejbName == null)
         throw new IllegalArgumentException("ejbName is null");
      if(ejbMethod == null)
         throw new IllegalArgumentException("ejbMethod is null");
      if(ejbCS == null)
         throw new IllegalArgumentException("EJB CodeSource is null");
      if(contextID == null)
         throw new IllegalArgumentException("ContextID is null");
      if(callerSubject == null && callerRunAs == null)
         throw new IllegalArgumentException("Either callerSubject or callerRunAs should be non-null"); 

      AuthorizationManager am = securityContext.getAuthorizationManager();
      if(am == null)
         throw new IllegalStateException("Authorization Manager is null");

      HashMap<String,Object> map =  new HashMap<String,Object>();
      try
      {
         if(this.policyRegistration == null)
            this.policyRegistration = getPolicyRegistrationFromJNDI(); 
      }
      catch(Exception e)
      {
         log.error("Error getting Policy Registration",e);
      }
      
      map.put(ResourceKeys.POLICY_REGISTRATION, this.policyRegistration); 
     
      EJBResource ejbResource = new EJBResource(map);
      ejbResource.setEjbVersion(version);
      ejbResource.setPolicyContextID(contextID);
      ejbResource.setCallerRunAsIdentity(callerRunAs);
      ejbResource.setEjbName(ejbName);
      ejbResource.setEjbMethod(ejbMethod);
      ejbResource.setPrincipal(ejbPrincipal);
      ejbResource.setEjbMethodInterface(invocationInterfaceString);
      ejbResource.setCodeSource(ejbCS);
      ejbResource.setCallerRunAsIdentity(callerRunAs);
      ejbResource.setCallerSubject(callerSubject);
      ejbResource.setEjbMethodRoles(methodRoles);
      
      SecurityContextCallbackHandler sch = new SecurityContextCallbackHandler(this.securityContext); 
      RoleGroup callerRoles = am.getSubjectRoles(callerSubject, sch);
      
      boolean isAuthorized = false;
      try
      {
         int check = am.authorize(ejbResource, callerSubject, callerRoles);
         isAuthorized = (check == AuthorizationContext.PERMIT);
         authorizationAudit((isAuthorized ? AuditLevel.SUCCESS : AuditLevel.FAILURE)
                             ,ejbResource, null);
      }
      catch (Exception e)
      {
         isAuthorized = false;
         if(log.isTraceEnabled())
            log.trace("Error in authorization:",e); 
         authorizationAudit(AuditLevel.ERROR,ejbResource,e);
      } 
      
      return isAuthorized;
   }

   @Override
   public boolean isCallerInRole(
         String roleName, 
         String ejbName, 
         Principal ejbPrincipal,
         Subject callerSubject, 
         String contextID,
         Set<SecurityRoleRef> securityRoleRefs)
   {
      return this.isCallerInRole(roleName, ejbName, ejbPrincipal, 
            callerSubject, contextID, securityRoleRefs, false); 
   }

   @Override
   public boolean isCallerInRole(String roleName, String ejbName, Principal ejbPrincipal, Subject callerSubject,
         String contextID, Set<SecurityRoleRef> securityRoleRefs, boolean enforceEJBRestrictions)
   { 
      if(roleName == null)
         throw new IllegalArgumentException("roleName is null");
      if(ejbName == null)
         throw new IllegalArgumentException("ejbName is null"); 
      if(contextID == null)
         throw new IllegalArgumentException("ContextID is null");  

      boolean isAuthorized = false;
      AuthorizationManager am = securityContext.getAuthorizationManager();
      
      if(am == null)
         throw new IllegalStateException("AuthorizationManager is null");
      
      HashMap<String,Object> map = new HashMap<String,Object>();

      try
      {
         if(this.policyRegistration == null)
            this.policyRegistration = getPolicyRegistrationFromJNDI(); 
      }
      catch(Exception e)
      {
         log.error("Error getting Policy Registration",e);
      }
      
      map.put(ResourceKeys.POLICY_REGISTRATION, this.policyRegistration);
      
      map.put(ResourceKeys.ROLENAME, roleName);
      map.put(ResourceKeys.ROLEREF_PERM_CHECK, Boolean.TRUE); 
      
      EJBResource ejbResource = new EJBResource(map);
      ejbResource.setPolicyContextID(contextID);
      
      RunAs callerRunAs = SecurityActions.getIncomingRunAs(securityContext);
      
      ejbResource.setEjbVersion(version);
      ejbResource.setEjbName(ejbName);
      ejbResource.setPrincipal(ejbPrincipal);
      ejbResource.setCallerRunAsIdentity(callerRunAs);
      ejbResource.setSecurityRoleReferences(securityRoleRefs); 
      ejbResource.setEnforceEJBRestrictions(enforceEJBRestrictions);
      
      ejbResource.setCallerSubject(callerSubject);
      SecurityContextCallbackHandler sch = new SecurityContextCallbackHandler(this.securityContext); 
      RoleGroup callerRoles = am.getSubjectRoles(callerSubject, sch);
      
      try
      {
         int check = am.authorize(ejbResource, callerSubject, callerRoles);
         isAuthorized = (check == AuthorizationContext.PERMIT);
      } 
      catch (Exception e)
      {
         isAuthorized = false; 
         if(log.isTraceEnabled()) 
            log.trace(roleName + "::isCallerInRole check failed:"+e.getLocalizedMessage(), e); 
         authorizationAudit(AuditLevel.ERROR,ejbResource,e);  
      } 
      return isAuthorized; 
   }

   @Override
   public String getEJBVersion()
   {
      return this.version;
   }
   
   @Override
   public void setEJBVersion(String ejbVersion)
   {
      /**
       * Validate the argument
       */ 
      if(EJBResource.EJB_VERSION_1_1.equalsIgnoreCase(ejbVersion) ||
            EJBResource.EJB_VERSION_2_0.equalsIgnoreCase(ejbVersion) ||
            EJBResource.EJB_VERSION_3_0.equalsIgnoreCase(ejbVersion))
      {
          this.version = ejbVersion;  
      }
      else
         throw new IllegalArgumentException("Invalid ejbVersion:" + ejbVersion);
   }
   
   
   private PolicyRegistration getPolicyRegistrationFromJNDI() throws Exception
   {
      return (PolicyRegistration) (new InitialContext()).lookup("java:/policyRegistration");
   }
}