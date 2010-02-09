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
package org.jboss.security.microcontainer.beans.metadata;

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlNsForm;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;
import javax.xml.bind.annotation.XmlType;

import org.jboss.beans.metadata.spi.BeanMetaData;
import org.jboss.beans.metadata.spi.BeanMetaDataFactory;
import org.jboss.beans.metadata.spi.ValueMetaData;
import org.jboss.beans.metadata.spi.builder.BeanMetaDataBuilder;
import org.jboss.logging.Logger;
import org.jboss.security.microcontainer.beans.ACLPolicyBean;
import org.jboss.security.microcontainer.beans.ApplicationPolicyBean;
import org.jboss.security.microcontainer.beans.AuditPolicyBean;
import org.jboss.security.microcontainer.beans.AuthenticationPolicyBean;
import org.jboss.security.microcontainer.beans.AuthorizationPolicyBean;
import org.jboss.security.microcontainer.beans.IdentityTrustPolicyBean;
import org.jboss.security.microcontainer.beans.JASPIAuthenticationPolicyBean;
import org.jboss.security.microcontainer.beans.MappingPolicyBean;
import org.jboss.xb.annotations.JBossXmlSchema;

/**
 * <p>
 * This class represents the {@code <application-policy>} element in a security configuration. It is also a
 * {@code BeanMetaDataFactory} implementation that uses all the metadata created during the XB parse to build an
 * instance of {@code ApplicationPolicyBean}.
 * </p>
 * <p>
 * An example of {@code <application-policy>} configuration is as follows:
 * 
 * <pre>
 * &lt;deployment xmlns=&quot;urn:jboss:bean-deployer:2.0&quot;&gt;
 * 
 *    &lt;application-policy xmlns=&quot;urn:jboss:security-beans:1.0&quot; name=&quot;TestPolicy1&quot;&gt;
 *       &lt;authentication&gt;
 *          &lt;login-module code=&quot;org.jboss.security.auth.spi.UsersRolesLoginModule&quot; flag=&quot;required&quot;&gt;
 *             &lt;module-option name=&quot;usersProperties&quot;&gt;jboss-users.properties&lt;/module-option&gt;
 *             &lt;module-option name=&quot;rolesProperties&quot;&gt;jboss-roles.properties&lt;/module-option&gt;
 *          &lt;/login-module&gt;
 *       &lt;/authentication&gt;
 *    &lt;/application-policy&gt;
 *    ...
 * &lt;/deployment&gt;
 * </pre>
 * 
 * The information parsed from an {@code <application-policy>} configuration is used to create a graph of metadata
 * classes that has this class as root. Being a {@code BeanMetaDataFactory}, this class uses the metadata graph to
 * create an instance of {@code ApplicationPolicyBean} and all correlated beans, registering them with the
 * microcontainer.
 * </p>
 * 
 * @see org.jboss.security.microcontainer.beans.ApplicationPolicyBean
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
@JBossXmlSchema(namespace = "urn:jboss:security-beans:1.0", elementFormDefault = XmlNsForm.QUALIFIED)
@XmlRootElement(name = "application-policy")
@XmlType(name = "applicationPolicyType", propOrder = {"authentication", "jaspiAuthentication", "authorization", "acl",
      "roleMapping", "mapping", "audit", "identityTrust"})
public class ApplicationPolicyMetaDataFactory implements BeanMetaDataFactory
{

   private static final String DEFAUL_SEC_MANAGEMENT = "JNDIBasedSecurityManagement";

   /** the name of the application policy. */
   private String policyName;

   /** the name of the parent policy, if any. */
   private String parentPolicy;

   /** the name of the security management bean. */
   private String securityManagement = DEFAUL_SEC_MANAGEMENT;

   /** the metadata of the authentication policy. */
   private AuthenticationMetaData authMetaData;

   /** the metadata of the jaspi authentication policy. */
   private JASPIAuthenticationMetaData jaspiMetaData;

   /** the metadata of the authorization policy. */
   private AuthorizationMetaData authzMetaData;

   /** the metadata of the acl policy. */
   private ACLMetaData aclMetaData;

   /** the metadata of the role-mapping policy. */
   private MappingMetaData roleMappingMetaData;

   /** the metadata of the generic mapping policy. */
   private MappingMetaData mappingMetaData;
   
   /** the metadata of the audit policy. */
   private AuditMetaData auditMetaData;

   /** the metadata of the identity-trust policy. */
   private IdentityTrustMetaData trustMetaData;

   protected static Logger logger = Logger.getLogger(ApplicationPolicyMetaDataFactory.class);

   /**
    * <p>
    * Sets the name of the application policy.
    * </p>
    * 
    * @param policyName a {@code String} representing the name to be set.
    */
   @XmlAttribute(name = "name", required = true)
   public void setPolicyName(String policyName)
   {
      this.policyName = policyName;
   }

   /**
    * <p>
    * Sets the name of the parent application policy, if applicable.
    * </p>
    * 
    * @param parentPolicy a {@code String} representing the name of the parent policy.
    */
   @XmlAttribute(name = "extends")
   public void setParentPolicy(String parentPolicy)
   {
      this.parentPolicy = parentPolicy;
   }

   /**
    * <p>
    * Sets the name of the security management bean that must be injected into the policy.
    * </p>
    * 
    * @param securityManagement a {@code String} representing the name of the management bean.
    */
   @XmlAttribute(name = "securityManagement")
   public void setSecurityManagement(String securityManagement)
   {
      this.securityManagement = securityManagement;
   }

   /**
    * <p>
    * Sets the metadata generated as a result of parsing the &lt;authentication&gt; element in an application policy
    * configuration.
    * </p>
    * 
    * @param authMetaData a reference to the generated {@code AuthenticationMetaData}.
    */
   @XmlElement(name = "authentication", type = AuthenticationMetaData.class)
   public void setAuthentication(AuthenticationMetaData authMetaData)
   {
      // authentication and authentication-jaspi are mutually exclusive.
      if (this.jaspiMetaData != null)
         throw new IllegalArgumentException(
               "An <authentication-jaspi> configuration has already been defined for the policy");
      this.authMetaData = authMetaData;
   }

   /**
    * <p>
    * Sets the metadata generated as a result of parsing the &lt;authentication-jaspi&gt; element in an application
    * policy configuration.
    * </p>
    * 
    * @param jaspiMetaData a reference to the generated {@code JASPIAuthenticationMetaData}.
    */
   @XmlElement(name = "authentication-jaspi", type = JASPIAuthenticationMetaData.class)
   public void setJaspiAuthentication(JASPIAuthenticationMetaData jaspiMetaData)
   {
      // authentication and authentication-jaspi are mutually exclusive.
      if (this.authMetaData != null)
         throw new IllegalArgumentException("An <authentication> configuration has already been defined for the policy");
      this.jaspiMetaData = jaspiMetaData;
   }

   /**
    * <p>
    * Sets the metadata generated as a result of parsing the &lt;authorization&gt; element in an application policy
    * configuration.
    * </p>
    * 
    * @param authzMetaData a reference to the generated {@code AuthorizationMetaData}.
    */
   @XmlElement(name = "authorization", type = AuthorizationMetaData.class)
   public void setAuthorization(AuthorizationMetaData authzMetaData)
   {
      this.authzMetaData = authzMetaData;
   }

   /**
    * <p>
    * Sets the metadata generated as a result of parsing the &lt;acl&gt; element in an application policy configuration.
    * </p>
    * 
    * @param aclMetaData a reference to the generated {@code ACLMetaData}.
    */
   @XmlElement(name = "acl", type = ACLMetaData.class)
   public void setAcl(ACLMetaData aclMetaData)
   {
      this.aclMetaData = aclMetaData;
   }

   /**
    * <p>
    * Sets the metadata generated as a result of parsing the &lt;rolemapping&gt; element in an application policy
    * configuration.
    * </p>
    * 
    * @param mappingMetaData a reference to the generated {@code MappingMetaData}.
    */
   @XmlElement(name = "rolemapping", type = MappingMetaData.class)
   public void setRoleMapping(MappingMetaData mappingMetaData)
   {
      this.roleMappingMetaData = mappingMetaData;
   }

   /**
    * <p>
    * Sets the metadata generated as a result of parsing the &lt;mapping&gt; element in an application policy
    * configuration.
    * </p>
    * 
    * @param mappingMetaData a reference to the generated {@code MappingMetaData}.
    */
   @XmlElement(name = "mapping", type = MappingMetaData.class)
   public void setMapping(MappingMetaData mappingMetaData)
   {
      this.mappingMetaData = mappingMetaData;
   }

   /**
    * <p>
    * Sets the metadata generated as a result of parsing the &lt;audit&gt; element in an application policy
    * configuration.
    * </p>
    * 
    * @param auditMetaData a reference to the generated {@code AuditMetaData}.
    */
   @XmlElement(name = "audit", type = AuditMetaData.class)
   public void setAudit(AuditMetaData auditMetaData)
   {
      this.auditMetaData = auditMetaData;
   }

   /**
    * <p>
    * Sets the metadata generated as a result of parsing the &lt;identity-trust&gt; element in an application policy
    * configuration.
    * </p>
    * 
    * @param trustMetaData a reference to the generated {@code IdentityTrustMetaData}.
    */
   @XmlElement(name = "identity-trust", type = IdentityTrustMetaData.class)
   public void setIdentityTrust(IdentityTrustMetaData trustMetaData)
   {
      this.trustMetaData = trustMetaData;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.beans.metadata.spi.BeanMetaDataFactory#getBeans()
    */
   @XmlTransient
   public List<BeanMetaData> getBeans()
   {
      List<BeanMetaData> result = new ArrayList<BeanMetaData>();
      logger.trace("Generating metadata for application-policy " + this.policyName);

      // create the metadata for the application policy bean.
      BeanMetaDataBuilder policyBuilder = BeanMetaDataBuilder.createBuilder(this.policyName,
            ApplicationPolicyBean.class.getName());
      policyBuilder.addPropertyMetaData("name", this.policyName);
      policyBuilder.addPropertyMetaData("parentPolicy", this.parentPolicy);
      result.add(policyBuilder.getBeanMetaData());

      // authentication metadata.
      if (this.authMetaData != null)
      {
         logger.trace("Generating authentication metadata for policy " + this.policyName);
         // get the metadata for the authentication policy bean.
         String authPolicyName = this.policyName + "$AuthenticationPolicy";
         result.addAll(this.authMetaData.getBeans(authPolicyName, AuthenticationPolicyBean.class.getName()));

         // inject the authentication policy into the application policy.
         ValueMetaData injectAuthenticationPolicy = policyBuilder.createInject(authPolicyName);
         policyBuilder.addPropertyMetaData("authenticationPolicy", injectAuthenticationPolicy);
      }
      else if (this.jaspiMetaData != null)
      {
         logger.trace("Generating jaspi-authentication metadata for policy " + this.policyName);
         // get the metadata for the jaspi authentication policy bean.
         String authPolicyName = this.policyName + "$JASPIAuthenticationPolicy";
         result.addAll(this.jaspiMetaData.getBeans(authPolicyName, JASPIAuthenticationPolicyBean.class.getName()));

         // inject the jaspi authentication policy into the application policy.
         ValueMetaData injectAuthenticationPolicy = policyBuilder.createInject(authPolicyName);
         policyBuilder.addPropertyMetaData("authenticationPolicy", injectAuthenticationPolicy);
      }
      // if no authentication configuration was found and the policy does not extend another policy, throw an exception.
      else if (this.parentPolicy == null)
      {
         throw new RuntimeException(
               "An application policy must have an authentication or authentication-jaspi configuration");
      }

      // authorization metadata.
      if (this.authzMetaData != null)
      {
         logger.trace("Generating authorization metadata for policy " + this.policyName);
         // get the metadata for the authorization policy bean.
         String authzPolicyName = this.policyName + "$AuthorizationPolicy";
         result.addAll(this.authzMetaData.getBeans(authzPolicyName, AuthorizationPolicyBean.class.getName()));

         // inject the authorization policy into the application policy.
         ValueMetaData injectAuthorizationPolicy = policyBuilder.createInject(authzPolicyName);
         policyBuilder.addPropertyMetaData("authorizationPolicy", injectAuthorizationPolicy);
      }

      // acl (instance-based authorization) metadata.
      if (this.aclMetaData != null)
      {
         logger.trace("Generating acl metadata for policy " + this.policyName);
         // get the metadata for the acl policy bean.
         String aclPolicyName = this.policyName + "$ACLPolicy";
         result.addAll(this.aclMetaData.getBeans(aclPolicyName, ACLPolicyBean.class.getName()));

         // inject the authorization policy into the application policy.
         ValueMetaData injectACLPolicy = policyBuilder.createInject(aclPolicyName);
         policyBuilder.addPropertyMetaData("aclPolicy", injectACLPolicy);
      }

      // role-mapping metadata.
      if (this.roleMappingMetaData != null)
      {
         logger.trace("Generating role-mapping metadata for policy " + this.policyName);
         // get the metadata for the role-mapping policy bean.
         String mappingPolicyName = this.policyName + "$RoleMappingPolicy";
         result.addAll(this.roleMappingMetaData.getBeans(mappingPolicyName, MappingPolicyBean.class.getName()));

         // inject the role-mapping policy into the application policy.
         ValueMetaData injectMappingPolicy = policyBuilder.createInject(mappingPolicyName);
         policyBuilder.addPropertyMetaData("roleMappingPolicy", injectMappingPolicy);
      }

      // generic mapping metadata.
      if (this.mappingMetaData != null)
      {
         logger.trace("Generating mapping metadata for policy " + this.policyName);
         // get the metadata for the mapping policy bean.
         String mappingPolicyName = this.policyName + "$MappingPolicy";
         result.addAll(this.mappingMetaData.getBeans(mappingPolicyName, MappingPolicyBean.class.getName()));

         // inject the mapping policy into the application policy.
         ValueMetaData injectMappingPolicy = policyBuilder.createInject(mappingPolicyName);
         policyBuilder.addPropertyMetaData("mappingPolicy", injectMappingPolicy);
      }

      // audit metadata.
      if (this.auditMetaData != null)
      {
         logger.trace("Generating audit metadata for policy " + this.policyName);
         // get the metadata for the audit policy bean.
         String auditPolicyName = this.policyName + "$AuditPolicy";
         result.addAll(this.auditMetaData.getBeans(auditPolicyName, AuditPolicyBean.class.getName()));

         // inject the audit policy into the application policy.
         ValueMetaData injectAuditPolicy = policyBuilder.createInject(auditPolicyName);
         policyBuilder.addPropertyMetaData("auditPolicy", injectAuditPolicy);
      }

      // identity-trust metadata.
      if (this.trustMetaData != null)
      {
         logger.trace("Generating identity-trust metadata for policy " + this.policyName);
         // get the metadata for the identity-trust policy bean.
         String trustPolicyName = this.policyName + "$IdentityTrustPolicy";
         result.addAll(this.trustMetaData.getBeans(trustPolicyName, IdentityTrustPolicyBean.class.getName()));

         // inject the identity-trust policy into the application policy.
         ValueMetaData injectIdentityTrustPolicy = policyBuilder.createInject(trustPolicyName);
         policyBuilder.addPropertyMetaData("identityTrustPolicy", injectIdentityTrustPolicy);
      }

      // inject the security management bean.
      logger.trace("Injecting security management " + this.securityManagement + " into application-policy metadata");
      ValueMetaData injectManagement = policyBuilder.createInject(this.securityManagement);
      policyBuilder.addPropertyMetaData("securityManagement", injectManagement);

      return result;
   }
}
