/*
  * JBoss, Home of Professional Open Source
  * Copyright 2005, JBoss Inc., and individual contributors as indicated
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
package org.jboss.security.authorization.modules.ejb;

import java.util.Map;

import javax.security.auth.Subject;

import org.jboss.logging.Logger;
import org.jboss.security.authorization.AuthorizationContext;
import org.jboss.security.authorization.PolicyRegistration;
import org.jboss.security.authorization.Resource;
import org.jboss.security.authorization.ResourceKeys;
import org.jboss.security.authorization.modules.AuthorizationModuleDelegate;
import org.jboss.security.authorization.resources.EJBResource;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.xacml.interfaces.PolicyDecisionPoint;
import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.jboss.security.xacml.interfaces.XACMLConstants;
 

//$Id$

/**
 *  Authorization Module Delegate that deals with the authorization decisions
 *  for the EJB Layer
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @since  Jul 6, 2006 
 *  @version $Revision$
 */
public class EJBXACMLPolicyModuleDelegate extends EJBPolicyModuleDelegate
{   
   private String policyContextID;
   
   public EJBXACMLPolicyModuleDelegate()
   {
     log = Logger.getLogger(getClass());
     trace = log.isTraceEnabled();
   }
   
   /**
    * @see AuthorizationModuleDelegate#authorize(Resource)
    */
   public int authorize(Resource resource, Subject callerSubject, RoleGroup role)
   {
      if(resource instanceof EJBResource == false)
         throw new IllegalArgumentException("resource is not an EJBResource");
      
      EJBResource ejbResource = (EJBResource) resource;
      
      //Get the context map
      Map<String,Object> map = resource.getMap();
      if(map == null)
         throw new IllegalStateException("Map from the Resource is null");

      this.policyRegistration = (PolicyRegistration) map.get(ResourceKeys.POLICY_REGISTRATION);  
      if(this.policyRegistration == null)
         throw new IllegalStateException("Policy Registration passed is null");

      this.callerRunAs = ejbResource.getCallerRunAsIdentity();
      this.ejbName = ejbResource.getEjbName();
      this.ejbMethod = ejbResource.getEjbMethod();
      this.ejbPrincipal = ejbResource.getPrincipal();
      this.policyContextID = ejbResource.getPolicyContextID();
      if(policyContextID == null)
         throw new IllegalStateException("Context ID is null"); 
      
      this.securityRoleReferences = ejbResource.getSecurityRoleReferences();
      
      //isCallerInRole checks
      this.roleName = (String)map.get(ResourceKeys.ROLENAME); 
      
      Boolean roleRefCheck = checkBooleanValue((Boolean)map.get(ResourceKeys.ROLEREF_PERM_CHECK)); 
      if(roleRefCheck)
         return checkRoleRef(role); //Base class handles this
      
      return process(role);
   } 
   
   //Private Methods
   /**
    * Process the ejb request
    * @param request
    * @param sc
    * @return
    */ 
   private int process(RoleGroup callerRoles) 
   { 
      int result = AuthorizationContext.DENY;
      EJBXACMLUtil util = new EJBXACMLUtil();
      try
      {
         RequestContext requestCtx = util.createXACMLRequest(this.ejbName,
               this.ejbMethod, this.ejbPrincipal, callerRoles);
         
         PolicyDecisionPoint pdp = util.getPDP(policyRegistration, this.policyContextID); 
         if(pdp == null)
            throw new IllegalStateException("PDP is null");
         
         ResponseContext response = pdp.evaluate(requestCtx);
         result = response.getDecision() == XACMLConstants.DECISION_PERMIT ? 
               AuthorizationContext.PERMIT : AuthorizationContext.DENY;
      }
      catch(Exception e)
      {
         if(trace)
            log.trace("Exception in processing:",e);
         result = AuthorizationContext.DENY;
      }  
      return result;
   } 
   
   /**
    * Ensure that the bool is a valid value
    * @param bool
    * @return bool or Boolean.FALSE (when bool is null)
    */
   private Boolean checkBooleanValue(Boolean bool)
   {
      if(bool == null)
         return Boolean.FALSE;
      return bool;
   } 
}