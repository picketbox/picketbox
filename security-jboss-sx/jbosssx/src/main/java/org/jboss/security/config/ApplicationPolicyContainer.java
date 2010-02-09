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
package org.jboss.security.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;
import javax.xml.namespace.QName;

import org.jboss.logging.Logger;
import org.jboss.security.audit.config.AuditProviderEntry;
import org.jboss.security.auth.container.config.AuthModuleEntry;
import org.jboss.security.auth.login.AppConfigurationEntryHolder;
import org.jboss.security.auth.login.AuthenticationInfo;
import org.jboss.security.auth.login.BaseAuthenticationInfo;
import org.jboss.security.auth.login.JASPIAuthenticationInfo;
import org.jboss.security.auth.login.LoginModuleStackHolder;
import org.jboss.security.authorization.config.AuthorizationConfigEntryHolder;
import org.jboss.security.authorization.config.AuthorizationModuleEntry;
import org.jboss.security.identitytrust.config.IdentityTrustModuleEntry;
import org.jboss.xb.binding.GenericValueContainer;

// $Id$

/**
 * A container for creating ApplicationPolicy during jbxb parse.
 * 
 * @author Anil.Saldhana@jboss.org
 * @version $Revision$
 */
public class ApplicationPolicyContainer implements GenericValueContainer
{
   private static Logger log = Logger.getLogger(ApplicationPolicyContainer.class);

   ApplicationPolicy info = null;

   String authName = null;

   String baseAppPolicyName = null;

   @SuppressWarnings("unchecked")
   List authenticationModuleEntries = new ArrayList();

   List<AuthorizationModuleEntry> authorizationModuleEntries = new ArrayList<AuthorizationModuleEntry>();

   List<AuditProviderEntry> auditProviderEntries = new ArrayList<AuditProviderEntry>();

   List<IdentityTrustModuleEntry> identityTrustModuleEntries = new ArrayList<IdentityTrustModuleEntry>();

   Map<String, LoginModuleStackHolder> loginModuleStackMap = new HashMap<String, LoginModuleStackHolder>();

   boolean isJASPIAuthentication = false;

   boolean isJAASAuthentication = false;

   boolean isAuthorization = false;

   boolean containsAudit = false;

   boolean containsIdentityTrust = false;

   boolean containsRoleMapping = false;

   // Mapping Info Object
   Map<String,MappingInfo> mappingInfos = new HashMap<String,MappingInfo>();

   ACLInfo aclInfo = null;

   AuditInfo auditInfo = null;

   IdentityTrustInfo identityTrustInfo = null;

   /**
    * @see GenericValueContainer#addChild(javax.xml.namespace.QName, java.lang.Object)
    */
   @SuppressWarnings("unchecked")
   public void addChild(QName name, Object value)
   {
      log.debug("addChild::" + name + ":" + value);
      if ("name".equals(name.getLocalPart()))
      {
         authName = (String) value;
      }
      else if ("extends".equals(name.getLocalPart()))
      {
         baseAppPolicyName = (String) value;
      }
      else if (value instanceof AppConfigurationEntryHolder)
      {
         AppConfigurationEntryHolder ace = (AppConfigurationEntryHolder) value;
         authenticationModuleEntries.add(ace.getEntry());
         isJAASAuthentication = true;
      }
      else if (value instanceof AppConfigurationEntry)
      {
         AppConfigurationEntry ace = (AppConfigurationEntry) value;
         authenticationModuleEntries.add(ace);
         isJAASAuthentication = true;
      }
      else if (value instanceof AuthModuleEntry)
      {
         AuthModuleEntry ame = (AuthModuleEntry) value;
         // Check if the authmodule needs a reference to a loginmodulestack
         String lmshName = ame.getLoginModuleStackHolderName();
         if (lmshName != null)
            ame.setLoginModuleStackHolder(loginModuleStackMap.get(lmshName));
         authenticationModuleEntries.add(ame);
         isJASPIAuthentication = true;
      }
      else if (value instanceof LoginModuleStackHolder)
      {
         LoginModuleStackHolder lmsh = (LoginModuleStackHolder) value;
         loginModuleStackMap.put(lmsh.getName(), lmsh);
         isJASPIAuthentication = true;
      }
      else if (value instanceof AuthorizationModuleEntry)
      {
         AuthorizationModuleEntry ame = (AuthorizationModuleEntry) value;
         if (!authorizationModuleEntries.contains(ame))
            authorizationModuleEntries.add(ame);
         isAuthorization = true;
      }
      else if (value instanceof AuthorizationConfigEntryHolder)
      {
         AuthorizationConfigEntryHolder ame = (AuthorizationConfigEntryHolder) value;
         AuthorizationModuleEntry ameEntry = ame.getEntry();
         if (!authorizationModuleEntries.contains(ameEntry))
            authorizationModuleEntries.add(ameEntry);
         isAuthorization = true;
      }
      else if (value instanceof AuditProviderEntry)
      {
         AuditProviderEntry ameEntry = (AuditProviderEntry) value;
         if (!auditProviderEntries.contains(ameEntry))
            auditProviderEntries.add(ameEntry);
         containsAudit = true;
      }
      else if (value instanceof IdentityTrustModuleEntry)
      {
         IdentityTrustModuleEntry ameEntry = (IdentityTrustModuleEntry) value;
         if (!identityTrustModuleEntries.contains(ameEntry))
            identityTrustModuleEntries.add(ameEntry);
         containsIdentityTrust = true;
      }
   }

   /**
    * Mapping Objects are added to the Application Policy
    * 
    * @param obj
    */
   @SuppressWarnings("unchecked")
   public void addMappingInfo(Object obj)
   {
      log.debug(obj);
      if (obj instanceof Map)
      {
         this.mappingInfos.putAll((Map) obj);
         for(MappingInfo info: this.mappingInfos.values())
            info.setName(authName);
         this.containsRoleMapping = true;
      }
   }

   /**
    * <p>
    * Adds the {@code ACLInfo} object constructed by the XB parse to the application policy.
    * </p>
    * 
    * @param info a reference to the {@code ACLInfo} being added.
    */
   public void addACLInfo(Object info)
   {
      if (info instanceof ACLInfo)
      {
         this.aclInfo = (ACLInfo) info;
         this.aclInfo.setName(this.authName);
      }
   }

   /**
    * @see GenericValueContainer#instantiate()
    */
   @SuppressWarnings("unchecked")
   public Object instantiate()
   {
      info = new ApplicationPolicy(authName);
      if (baseAppPolicyName != null)
         info.setBaseApplicationPolicyName(baseAppPolicyName);

      BaseAuthenticationInfo binfo = null;
      AuthorizationInfo ainfo = null;

      if (isJAASAuthentication)
      {
         binfo = new AuthenticationInfo(authName);
         SecurityActions.addModules(binfo, authenticationModuleEntries);
         info.setAuthenticationInfo(binfo);
      }
      if (isJASPIAuthentication)
      {
         JASPIAuthenticationInfo jaspiInfo = new JASPIAuthenticationInfo(authName);
         SecurityActions.addModules(jaspiInfo, authenticationModuleEntries);
         for (LoginModuleStackHolder holder : this.loginModuleStackMap.values())
            jaspiInfo.add(holder);
         info.setAuthenticationInfo(jaspiInfo);
      }
      if (isAuthorization)
      {
         ainfo = new AuthorizationInfo(authName);
         SecurityActions.addModules(ainfo, authorizationModuleEntries);
         info.setAuthorizationInfo(ainfo);
      }
      if (this.aclInfo != null)
      {
         info.setAclInfo(this.aclInfo);
      }
      if (containsRoleMapping)
      {
         for(String type : this.mappingInfos.keySet())
            info.setMappingInfo(type, this.mappingInfos.get(type));
      }
      if (containsAudit)
      {
         auditInfo = new AuditInfo(authName);
         SecurityActions.addModules(auditInfo, auditProviderEntries);
         info.setAuditInfo(auditInfo);
      }
      if (containsIdentityTrust)
      {
         identityTrustInfo = new IdentityTrustInfo(authName);
         SecurityActions.addModules(identityTrustInfo, identityTrustModuleEntries);
         info.setIdentityTrustInfo(identityTrustInfo);
      }
      return info;
   }

   /**
    * @see GenericValueContainer#getTargetClass()
    */
   public Class<?> getTargetClass()
   {
      return ApplicationPolicy.class;
   }
}
