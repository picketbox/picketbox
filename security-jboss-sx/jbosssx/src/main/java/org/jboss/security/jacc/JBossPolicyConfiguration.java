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
package org.jboss.security.jacc;

import java.security.Permission;
import java.security.PermissionCollection;

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyContextException;

import org.jboss.logging.Logger;
import org.jboss.security.util.state.IllegalTransitionException;
import org.jboss.security.util.state.State;
import org.jboss.security.util.state.StateMachine;

/** The JACC PolicyConfiguration implementation. This class associates a
 * context id with the permission ops it passes along to the global
 * DelegatingPolicy instance.
 *
 * @author Scott.Stark@jboss.org
 * @version $Revision$
 */
public class JBossPolicyConfiguration
   implements PolicyConfiguration
{
   private static Logger log = Logger.getLogger(JBossPolicyConfiguration.class);
   /** The JACC context id associated with the policy */
   private String contextID;
   /** The Policy impl which handles the JACC permissions */
   private DelegatingPolicy policy;
   /** A state machine whihc enforces the state behavior of this config */
   private StateMachine configStateMachine;
   /** A trace level logging flag set when the policy is created */
   private boolean trace;

   protected JBossPolicyConfiguration(String contextID, DelegatingPolicy policy,
      StateMachine configStateMachine)
      throws PolicyContextException
   {
      this.contextID = contextID;
      this.policy = policy;
      this.configStateMachine = configStateMachine;

      if (contextID == null)
         throw new IllegalArgumentException("contextID cannot be null");
      if (policy == null)
         throw new IllegalArgumentException("policy cannot be null");
      if (configStateMachine == null)
         throw new IllegalArgumentException("configStateMachine cannot be null");

      validateState("getPolicyConfiguration");
      trace = log.isTraceEnabled();
      if( trace )
         log.trace("ctor, contextID="+contextID);
   }

   void initPolicyConfiguration(boolean remove)
      throws PolicyContextException
   {
      validateState("getPolicyConfiguration");
      policy.initPolicyConfiguration(contextID, remove);
   }

   public void addToExcludedPolicy(Permission permission)
      throws PolicyContextException
   {
      if( trace )
         log.trace("addToExcludedPolicy, p="+permission);
      validateState("addToExcludedPolicy");
      policy.addToExcludedPolicy(contextID, permission);
   }
   
   public void addToExcludedPolicy(PermissionCollection permissions)
      throws PolicyContextException
   {
      if( trace )
         log.trace("addToExcludedPolicy, pc="+permissions);
      validateState("addToExcludedPolicy");
      policy.addToExcludedPolicy(contextID, permissions);
   }

   public void addToRole(String roleName, Permission permission)
      throws PolicyContextException
   {
      if( trace )
         log.trace("addToRole, roleName="+roleName+", p="+permission);
      validateState("addToRole");
      policy.addToRole(contextID, roleName, permission);
   }

   public void addToRole(String roleName, PermissionCollection permissions)
      throws PolicyContextException
   {
      if( trace )
         log.trace("addToRole, roleName="+roleName+", pc="+permissions);
      validateState("addToRole");
      policy.addToRole(contextID, roleName, permissions);
   }

   public void addToUncheckedPolicy(Permission permission)
      throws PolicyContextException
   {
      if( trace )
         log.trace("addToUncheckedPolicy, p="+permission);
      validateState("addToUncheckedPolicy");
      policy.addToUncheckedPolicy(contextID, permission);
   }

   public void addToUncheckedPolicy(PermissionCollection permissions)
      throws PolicyContextException
   {
      if( trace )
         log.trace("addToUncheckedPolicy, pc="+permissions);
      validateState("addToUncheckedPolicy");
      policy.addToUncheckedPolicy(contextID, permissions);
   }

   public void commit()
      throws PolicyContextException
   {
      if( trace )
         log.trace("commit:" + contextID);
      validateState("commit");
      policy.commit(contextID);
   }

   public void delete()
      throws PolicyContextException
   {
      if( trace )
         log.trace("delete:" + contextID);
      validateState("delete");
      policy.delete(contextID);
   }

   public String getContextID()
      throws PolicyContextException
   {
      validateState("getContextID");
      return contextID;
   }

   public boolean inService()
      throws PolicyContextException
   {
      validateState("inService");
      State state = configStateMachine.getCurrentState();
      boolean inService = state.getName().equals("inService");
      return inService;
   }

   public void linkConfiguration(PolicyConfiguration link)
      throws PolicyContextException
   {
      if( trace )
         log.trace("linkConfiguration, linkTo: "+link.getContextID());
      validateState("linkConfiguration");
      policy.linkConfiguration(contextID, link);
   }

   public void removeExcludedPolicy()
      throws PolicyContextException
   {
      if( trace )
         log.trace("removeExcludedPolicy");
      validateState("removeExcludedPolicy");
      policy.removeExcludedPolicy(contextID);
   }

   public void removeRole(String roleName)
      throws PolicyContextException
   {
      if( trace )
         log.trace("removeRole: "+roleName);
      validateState("removeRole");
      policy.removeRole(contextID, roleName);
   }

   public void removeUncheckedPolicy()
      throws PolicyContextException
   {
      if( trace )
         log.trace("removeUncheckedPolicy");
      validateState("removeUncheckedPolicy");
      policy.removeUncheckedPolicy(contextID);
   }

   protected void validateState(String action)
      throws PolicyContextException
   {
      try
      {
         configStateMachine.nextState(action);
      }
      catch(IllegalTransitionException e)
      {
         log.debug("validateState failure", e);
         throw new PolicyContextException("Operation not allowed", e);
      }
   }
}
