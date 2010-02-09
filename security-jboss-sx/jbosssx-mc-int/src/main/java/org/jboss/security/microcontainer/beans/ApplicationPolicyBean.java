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
package org.jboss.security.microcontainer.beans;

import java.util.Map;

import org.jboss.logging.Logger;
import org.jboss.security.AuthenticationManager;
import org.jboss.security.AuthorizationManager;
import org.jboss.security.ISecurityManagement;
import org.jboss.security.audit.AuditManager;
import org.jboss.security.auth.login.XMLLoginConfigImpl;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.ApplicationPolicyRegistration;
import org.jboss.security.config.MappingInfo;
import org.jboss.security.identitytrust.IdentityTrustManager;
import org.jboss.security.mapping.MappingManager;

/**
 * <p>
 * This class represents an application policy. An application policy describes the security requirements
 * (authentication, authorization, role-mapping, audit, and identity-trust) for a specific security domain. Each of
 * these requirements is described by the appropriate sub-policy.
 * </p>
 * <p>
 * Once this bean is started by the microcontainer it uses the information from all configured sub-policies to generate
 * an {@code org.jboss.security.config.ApplicationPolicy} and then registers the generated policy with the security
 * layer.
 * </p>
 * 
 * @see org.jboss.security.microcontainer.beans.BaseAuthenticationPolicy
 * @see org.jboss.security.microcontainer.beans.AuthorizationPolicyBean
 * @see org.jboss.security.microcontainer.beans.ACLPolicyBean
 * @see org.jboss.security.microcontainer.beans.MappingPolicyBean
 * @see org.jboss.security.microcontainer.beans.AuditPolicyBean
 * @see org.jboss.security.microcontainer.beans.IdentityTrustPolicyBean
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class ApplicationPolicyBean
{
   private static final String DEFAULT_NAME = "other";

   /** The application policy name. */
   private String name = DEFAULT_NAME;

   /** The name of the parent policy, if any. */
   private String parentPolicy;

   /** The authentication policy configured as part of this application policy. */
   private BaseAuthenticationPolicy<?> authenticationPolicy;

   /** the authorization policy configured as part of this application policy. */
   private AuthorizationPolicyBean authorizationPolicy;

   /** the acl (instance-based authorization) policy configured as part of this application policy. */
   private ACLPolicyBean aclPolicy;

   /** the role-mapping policy configured as part of this application policy. */
   private MappingPolicyBean roleMappingPolicy;
   
   /** the generic mapping policy configured as part of this application policy. */
   private MappingPolicyBean mappingPolicy;

   /** the audit policy configured as part of this application policy. */
   private AuditPolicyBean auditPolicy;

   /** the identity-trust policy configured as part of this application policy. */
   private IdentityTrustPolicyBean identityTrustPolicy;

   /** the security management implementation used by this bean to obtain the security managers. */
   private ISecurityManagement securityManagement;

   protected static Logger logger = Logger.getLogger(ApplicationPolicyBean.class);

   /**
    * <p>
    * Obtains the name of the application policy.
    * </p>
    * 
    * @return a {@code String} representing the name of the application policy.
    */
   public String getName()
   {
      return name;
   }

   /**
    * <p>
    * Sets the name of the application policy.
    * </p>
    * 
    * @param name a {@code String} representing the name to be set.
    */
   public void setName(String name)
   {
      this.name = name;
   }

   /**
    * <p>
    * Obtains the name of the parent policy.
    * </p>
    * 
    * @return a {@code String} representing the name of the parent policy.
    */
   public String getParentPolicy()
   {
      return parentPolicy;
   }

   /**
    * <p>
    * Sets the name of the parent policy.
    * </p>
    * 
    * @param parentPolicy a {@code String} representing the name of the parent policy to be set.
    */
   public void setParentPolicy(String parentPolicy)
   {
      this.parentPolicy = parentPolicy;
   }

   // getters and setters for the policy beans that form the application policy defined for the security domain.

   /**
    * <p>
    * Obtains the authentication policy that has been configured as part of this application policy.
    * </p>
    * 
    * @return a {@code BaseAuthenticationPolicy} representing the configured authentication policy.
    */
   public BaseAuthenticationPolicy<?> getAuthenticationPolicy()
   {
      return authenticationPolicy;
   }

   /**
    * <p>
    * Sets the authentication policy to be used by this application policy.
    * </p>
    * 
    * @param authenticationPolicy a {@code BaseAuthenticationPolicy} representing the policy to be set.
    */
   public void setAuthenticationPolicy(BaseAuthenticationPolicy<?> authenticationPolicy)
   {
      this.authenticationPolicy = authenticationPolicy;
   }

   /**
    * <p>
    * Obtains the authorization policy that has been configured as part of this application policy.
    * </p>
    * 
    * @return an {@code AuthorizationPolicyBean} representing the configured authorization policy.
    */
   public AuthorizationPolicyBean getAuthorizationPolicy()
   {
      return authorizationPolicy;
   }

   /**
    * <p>
    * Sets the authorization policy to be used by this application policy.
    * </p>
    * 
    * @param authorizationPolicy an {@code AuthorizationPolicyBean} representing the policy to be set.
    */
   public void setAuthorizationPolicy(AuthorizationPolicyBean authorizationPolicy)
   {
      this.authorizationPolicy = authorizationPolicy;
   }

   /**
    * <p>
    * Obtains the acl policy that has been configured as part of this application policy.
    * </p>
    * 
    * @return an {@code ACLPolicyBean} representing the configured acl policy.
    */
   public ACLPolicyBean getAclPolicy()
   {
      return aclPolicy;
   }

   /**
    * <p>
    * Sets the acl policy to be used by this application policy.
    * </p>
    * 
    * @param aclPolicy an {@code ACLPolicyBean} representing the policy to be set.
    */
   public void setAclPolicy(ACLPolicyBean aclPolicy)
   {
      this.aclPolicy = aclPolicy;
   }

   /**
    * <p>
    * Obtains the role-mapping policy that has been configured as part of this application policy.
    * </p>
    * 
    * @return a {@code MappingPolicyBean} representing the configured role-mapping policy.
    */
   public MappingPolicyBean getRoleMappingPolicy()
   {
      return roleMappingPolicy;
   }

   /**
    * <p>
    * Sets the role-mapping policy to be used by this application policy.
    * </p>
    * 
    * @param roleMappingPolicy a {@code MappingPolicyBean} representing the policy to be set.
    */
   public void setRoleMappingPolicy(MappingPolicyBean roleMappingPolicy)
   {
      this.roleMappingPolicy = roleMappingPolicy;
   }

   /**
    * <p>
    * Obtains the generic mapping policy that has been configured as part of this application policy.
    * </p>
    * 
    * @return a {@code MappingPolicyBean} representing the configured mapping policy.
    */
   public MappingPolicyBean getMappingPolicy()
   {
      return this.mappingPolicy;
   }

   /**
    * <p>
    * Sets the generic mapping policy to be used by this application policy.
    * </p>
    * 
    * @param mappingPolicy a {@code MappingPolicyBean} representing the policy to be set.
    */
   public void setMappingPolicy(MappingPolicyBean mappingPolicy)
   {
      this.mappingPolicy = mappingPolicy;
   }

   /**
    * <p>
    * Obtains the audit policy that has been configured as part of this application policy.
    * </p>
    * 
    * @return an {@code AuditPolicyBean} representing the configured audit policy.
    */
   public AuditPolicyBean getAuditPolicy()
   {
      return auditPolicy;
   }

   /**
    * <p>
    * Sets the audit policy to be used by this application policy.
    * </p>
    * 
    * @param auditPolicy an {@code AuditPolicyBean} representing the policy to be set.
    */
   public void setAuditPolicy(AuditPolicyBean auditPolicy)
   {
      this.auditPolicy = auditPolicy;
   }

   /**
    * <p>
    * Obtains the identity-trust policy that has been configured as part of this application policy.
    * </p>
    * 
    * @return an {@code IdentityTrustPolicyBean} representing the configured identity-trust policy.
    */
   public IdentityTrustPolicyBean getIdentityTrustPolicy()
   {
      return identityTrustPolicy;
   }

   /**
    * <p>
    * Sets the identity-trust policy to be used by this application policy.
    * </p>
    * 
    * @param identityTrustPolicy an {@code IdentityTrustPolicyBean} representing the policy to be set.
    */
   public void setIdentityTrustPolicy(IdentityTrustPolicyBean identityTrustPolicy)
   {
      this.identityTrustPolicy = identityTrustPolicy;
   }

   /**
    * <p>
    * Sets the {@code ISecurityManagement} implementation that must be used by this bean to obtain the various security
    * managers that enforce the security policies specified for the domain this bean represents.
    * </p>
    * 
    * @param securityManagement an implementation of the {@code ISecurityManagement} interface.
    */
   public void setSecurityManagement(ISecurityManagement securityManagement)
   {
      this.securityManagement = securityManagement;
   }

   // getter methods for the various security managers that enforce the policies defined for the security domain.

   /**
    * <p>
    * Obtains a reference to the {@code AuthenticationManager} that enforces the authentication policy.
    * </p>
    * 
    * @return the {@code AuthenticationManager} that authenticates users according to the specified policy, or
    *         {@code null} if no {@code AuthenticationManager} is available.
    */
   public AuthenticationManager getAuthenticationManager()
   {
      AuthenticationManager manager = null;
      if (this.securityManagement != null)
         manager = this.securityManagement.getAuthenticationManager(this.name);
      return manager;
   }

   /**
    * <p>
    * Obtains a reference to the {@code AuthorizationManager} that enforces the authorization policy.
    * </p>
    * 
    * @return the {@code AuthorizationManager} that authorizes access to resources according to the specified policy, or
    *         {@code null} if no {@code AuthorizationManager} is available.
    */
   public AuthorizationManager getAuthorizationManager()
   {
      AuthorizationManager manager = null;
      if (this.securityManagement != null)
         manager = this.securityManagement.getAuthorizationManager(this.name);
      return manager;
   }

   /**
    * <p>
    * Obtains a reference to the {@code MappingManager} that enforces the role-mapping policy.
    * </p>
    * 
    * @return the {@code MappingManager} that maps roles and identities according to the specified policy, or
    *         {@code null} if no {@code MappingManager} is available.
    */
   public MappingManager getMappingManager()
   {
      MappingManager manager = null;
      if (this.securityManagement != null)
         manager = this.securityManagement.getMappingManager(this.name);
      return manager;
   }

   /**
    * <p>
    * Obtains a reference to the {@code AuditManager} that enforces the audit policy.
    * </p>
    * 
    * @return the {@code AuditManager} that records security events according to the specified policy, or {@code null}
    *         if no {@code AuditManager} is available.
    */
   public AuditManager getAuditManager()
   {
      AuditManager manager = null;
      if (this.securityManagement != null)
         manager = this.securityManagement.getAuditManager(this.name);
      return manager;
   }

   /**
    * <p>
    * Obtains a reference to the {@code IdentityTrustManager} that enforces the identity-trust policy.
    * </p>
    * 
    * @return the {@code IdentityTrustManager} implementation to be used, or {@code null} if no
    *         {@code IdentityTrustManager} is available.
    */
   public IdentityTrustManager getIdentityTrustManager()
   {
      IdentityTrustManager manager = null;
      if (this.securityManagement != null)
         manager = this.securityManagement.getIdentityTrustManager(this.name);
      return manager;
   }

   // lifecycle methods.

   /**
    * <p>
    * Registers the application policy with the security framework once this bean has started.
    * </p>
    * 
    * @throws Exception if an error occurs while registering the application policy.
    */
   public void start() throws Exception
   {
      // create the application policy using the information from the beans and push it to the security layer.
      ApplicationPolicy policy = this.getApplicationPolicy();
      logger.trace("ApplicationPolicy " + this.name + " created " + policy);

      ApplicationPolicyRegistration policyRegistration = XMLLoginConfigImpl.getInstance();
      policyRegistration.addApplicationPolicy(this.name, policy);

      logger.trace("ApplicationPolicy " + this.name + " registered");
   }

   /**
    * <p>
    * Unregisters the application policy from the security framework when the bean stops.
    * </p>
    * 
    * @throws Exception if an error occurs while unregistering the application policy.
    */
   public void stop() throws Exception
   {
      // unregister the application policy.
      // TODO: flush the authentication cache of the domain being undeployed.
      XMLLoginConfigImpl.getInstance().removeApplicationPolicy(this.name);
      logger.trace("ApplicationPolicy " + this.name + " removed");
   }

   /**
    * <p>
    * Creates and return an {@code org.jboss.security.conf.ApplicationPolicy} object using the information contained in
    * this bean and in the sub-policies beans.
    * </p>
    * 
    * @return a reference to the constructed {@code ApplicationPolicy} object.
    */
   public ApplicationPolicy getApplicationPolicy()
   {
      ApplicationPolicy policy = new ApplicationPolicy(this.name);
      policy.setBaseApplicationPolicyName(this.parentPolicy);
      if (this.authenticationPolicy != null)
         policy.setAuthenticationInfo(this.authenticationPolicy.getPolicyInfo(this.name));
      if (this.authorizationPolicy != null)
         policy.setAuthorizationInfo(this.authorizationPolicy.getPolicyInfo(this.name));
      if (this.aclPolicy != null)
         policy.setAclInfo(this.aclPolicy.getPolicyInfo(this.name));
      if (this.roleMappingPolicy != null)
      {
         Map<String,MappingInfo> infosByType = this.roleMappingPolicy.getMappingInfoByType(this.name); 
         for(String type : infosByType.keySet())
            policy.setMappingInfo(type, infosByType.get(type));
      }
      if (this.mappingPolicy != null)
      {
         Map<String,MappingInfo> infosByType = this.mappingPolicy.getMappingInfoByType(this.name); 
         for(String type : infosByType.keySet())
            policy.setMappingInfo(type, infosByType.get(type));
      }
      if (this.auditPolicy != null)
         policy.setAuditInfo(this.auditPolicy.getPolicyInfo(this.name));
      if (this.identityTrustPolicy != null)
         policy.setIdentityTrustInfo(this.identityTrustPolicy.getPolicyInfo(this.name));

      return policy;
   }

   /*
    * (non-Javadoc)
    * 
    * @see java.lang.Object#toString()
    */
   @Override
   public String toString()
   {
      StringBuffer buffer = new StringBuffer("Application Policy Contents: " + this.name + "\n\n");
      if (this.authenticationPolicy != null)
         buffer.append(this.authenticationPolicy.toString());
      if (this.authorizationPolicy != null)
         buffer.append(this.authorizationPolicy.toString());
      if (this.aclPolicy != null)
         buffer.append(this.aclPolicy.toString());
      if (this.roleMappingPolicy != null)
         buffer.append(this.roleMappingPolicy.toString());
      if (this.mappingPolicy != null)
         buffer.append(this.mappingPolicy.toString());
      if (this.auditPolicy != null)
         buffer.append(this.auditPolicy.toString());
      if (this.identityTrustPolicy != null)
         buffer.append(this.identityTrustPolicy.toString());
      return buffer.toString();
   }
}
