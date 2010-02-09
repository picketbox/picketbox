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
package org.jboss.security.authorization.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jboss.logging.Logger;
import org.jboss.security.acl.config.ACLProviderEntry;
import org.jboss.security.audit.config.AuditProviderEntry;
import org.jboss.security.auth.login.LoginConfigObjectModelFactory;
import org.jboss.security.config.ACLInfo;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.AuditInfo;
import org.jboss.security.config.AuthorizationInfo;
import org.jboss.security.config.ControlFlag;
import org.jboss.security.config.IdentityTrustInfo;
import org.jboss.security.config.MappingInfo;
import org.jboss.security.config.ModuleOption;
import org.jboss.security.identitytrust.config.IdentityTrustModuleEntry;
import org.jboss.security.mapping.config.MappingModuleEntry;
import org.jboss.util.StringPropertyReplacer;
import org.jboss.xb.binding.UnmarshallingContext;
import org.xml.sax.Attributes;

// $Id$

/**
 * JBossXB Object Factory capable of parsing the security configuration file that can include both
 * authentication,authorization and mapping module configuration
 * 
 * @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 * @since Jun 9, 2006
 * @version $Revision$
 */
public class SecurityConfigObjectModelFactory extends LoginConfigObjectModelFactory
{
   private static Logger log = Logger.getLogger(SecurityConfigObjectModelFactory.class);

   private final boolean trace = log.isTraceEnabled();
 
   /**
    * <p>
    * Creates an instance of {@code SecurityConfigObjectModelFactory}.
    * </p>
    */
   public SecurityConfigObjectModelFactory()
   {
   }

   @Override
   public Object newChild(ApplicationPolicy aPolicy, UnmarshallingContext navigator, String namespaceUri,
         String localName, Attributes attrs)
   {
      Object child = super.newChild(aPolicy, navigator, namespaceUri, localName, attrs);
      if (child == null && "authorization".equals(localName))
      {
         child = new AuthorizationInfo(aPolicy.getName());
      }
      else if (child == null && "acl".equals(localName))
      {
         child = new ACLInfo(aPolicy.getName());
      }
      else if (child == null && "mapping".equals(localName))
      {
         child = new MappingInfo(aPolicy.getName());
      }
      else if (child == null && "rolemapping".equals(localName))
      {
         child = new MappingInfo(aPolicy.getName());
      }
      else if (child == null && "audit".equals(localName))
      {
         child = new AuditInfo(aPolicy.getName());
      }
      else if (child == null && "identity-trust".equals(localName))
      {
         child = new IdentityTrustInfo(aPolicy.getName());
      }
      return child;
   }

   // authorization
   public Object newChild(AuthorizationInfo info, UnmarshallingContext navigator, String namespaceUri,
         String localName, Attributes attrs)
   {
      Object child = null;
      if (trace)
         log.trace("newChild.AuthorizationInfo, localName: " + localName);
      if ("policy-module".equals(localName))
      {
         String code = attrs.getValue("code");
         code = StringPropertyReplacer.replaceProperties(code.trim());

         String flag = attrs.getValue("flag");
         if (flag == null)
            flag = "REQUIRED";
         flag = StringPropertyReplacer.replaceProperties(flag.trim());

         ControlFlag controlFlag = this.controlFlags.get(flag.toUpperCase());
         if (controlFlag == null)
            controlFlag = ControlFlag.REQUIRED;

         AuthorizationModuleEntry entry = new AuthorizationModuleEntry(code);
         entry.setControlFlag(controlFlag);

         child = entry;
         if (trace)
            log.trace("newChild.AuthorizationInfo, policy-module code: " + code);
      }

      return child;
   }

   public Object newChild(AuthorizationModuleEntry entry, UnmarshallingContext navigator, String namespaceUri,
         String localName, Attributes attrs)
   {
      Object child = null;
      if (trace)
         log.trace("newChild.AppConfigurationEntryHolder, localName: " + localName);
      if ("module-option".equals(localName))
      {
         String name = attrs.getValue("name");
         child = new ModuleOption(name);
         if (trace)
            log.trace("newChild.AuthModuleEntry, module-option name: " + name);
      }

      return child;
   }

   public void addChild(ApplicationPolicy aPolicy, AuthorizationInfo authInfo, UnmarshallingContext navigator,
         String namespaceURI, String localName)
   {
      aPolicy.setAuthorizationInfo(authInfo);
      if (trace)
         log.trace("addChild.ApplicationPolicy, name: " + aPolicy.getName());
   }

   public void addChild(AuthorizationInfo authInfo, AuthorizationConfigEntryHolder entryInfo,
         UnmarshallingContext navigator, String namespaceURI, String localName)
   {
      AuthorizationModuleEntry entry = entryInfo.getEntry();
      authInfo.add(entry);
      if (trace)
         log.trace("addChild.AuthorizationInfo, name: " + entry.getPolicyModuleName());
   }

   public void addChild(AuthorizationConfigEntryHolder entryInfo, ModuleOption option, UnmarshallingContext navigator,
         String namespaceURI, String localName)
   {
      entryInfo.addOption(option);
      if (trace)
         log.trace("addChild.AuthorizationConfigEntryHolder, name: " + option.getName());
   }

   public void addChild(AuthorizationInfo authInfo, AuthorizationModuleEntry entry, UnmarshallingContext navigator,
         String namespaceURI, String localName)
   {
      authInfo.add(entry);
   }

   public void addChild(AuthorizationModuleEntry entry, ModuleOption option, UnmarshallingContext navigator,
         String namespaceURI, String localName)
   {
      entry.add(option);
      if (trace)
         log.trace("addChild.AuthorizationModuleEntry, name: " + option.getName());
   }

   // Instance-based authorization (ACL)
   public Object newChild(ACLInfo info, UnmarshallingContext navigator, String namespaceUri, String localName,
         Attributes attrs)
   {
      Object child = null;
      if (trace)
         log.trace("newChild.ACLInfo, localName: " + localName);
      if ("acl-module".equals(localName))
      {
         String code = attrs.getValue("code");
         code = StringPropertyReplacer.replaceProperties(code.trim());

         String flag = attrs.getValue("flag");
         if (flag == null)
            flag = "REQUIRED";
         flag = StringPropertyReplacer.replaceProperties(flag.trim());

         ControlFlag controlFlag = this.controlFlags.get(flag.toUpperCase());
         if (controlFlag == null)
            controlFlag = ControlFlag.REQUIRED;

         ACLProviderEntry entry = new ACLProviderEntry(code);
         entry.setControlFlag(controlFlag);

         child = entry;
         if (trace)
            log.trace("newChild.ACLInfo, acl-module code: " + code);
      }

      return child;
   }

   public Object newChild(ACLProviderEntry entry, UnmarshallingContext navigator, String namespaceUri,
         String localName, Attributes attrs)
   {
      Object child = null;
      if (trace)
         log.trace("newChild.ACLProviderEntry, localName: " + localName);
      if ("module-option".equals(localName))
      {
         String name = attrs.getValue("name");
         child = new ModuleOption(name);
         if (trace)
            log.trace("newChild.trustProviderEntry, module-option name: " + name);
      }

      return child;
   }

   public void addChild(ApplicationPolicy aPolicy, ACLInfo aclInfo, UnmarshallingContext navigator,
         String namespaceURI, String localName)
   {
      aPolicy.setAclInfo(aclInfo);
      if (trace)
         log.trace("Adding ACLInfo as a child of ApplicationPolicy " + aPolicy.getName());
   }

   public void addChild(ACLInfo aclInfo, ACLProviderEntry aclEntry, UnmarshallingContext navigator,
         String namespaceURI, String localName)
   {
      aclInfo.add(aclEntry);
      if (trace)
         log.trace("Adding ACLProviderEntry " + aclEntry.getAclProviderName() + " to ACLInfo " + aclInfo.getName());
   }

   public void addChild(ACLProviderEntry aclEntry, ModuleOption option, UnmarshallingContext navigator,
         String namespaceURI, String localName)
   {
      aclEntry.add(option);
      if (trace)
         log.trace("Adding module-option " + option.getName() + " to ACLProviderEntry " + aclEntry.getAclProviderName());
   }

   // Mapping
   public Object newChild(MappingInfo info, UnmarshallingContext navigator, String namespaceUri, String localName,
         Attributes attrs)
   {
      Object child = null;
      if (trace)
         log.trace("newChild.MappingInfo, localName: " + localName);
      if ("mapping-module".equals(localName))
      {
         String code = attrs.getValue("code");
         code = StringPropertyReplacer.replaceProperties(code.trim());
         String type = attrs.getValue("type");
         if(type != null)
            type = StringPropertyReplacer.replaceProperties(type.trim());
         else
            type = "role";

         child = new MappingModuleEntry(code, new HashMap<String,Object>(), type);
         if (trace)
            log.trace("newChild.MappingInfo, mapping-module code: " + code + 
                  ", mapping-module type: " + type);
      }

      return child;
   }

   public Object newChild(MappingModuleEntry entry, UnmarshallingContext navigator, String namespaceUri,
         String localName, Attributes attrs)
   {
      Object child = null;
      if (trace)
         log.trace("newChild.MappingModuleEntry, localName: " + localName);
      if ("module-option".equals(localName))
      {
         String name = attrs.getValue("name");
         child = new ModuleOption(name);
         if (trace)
            log.trace("newChild.MappingModuleEntry, module-option name: " + name);
      }

      return child;
   }

   public void addChild(ApplicationPolicy aPolicy, MappingInfo authInfo, UnmarshallingContext navigator,
         String namespaceURI, String localName)
   {
      // first organize the mapping modules by type.
      Map<String,List<MappingModuleEntry>> mappings = new HashMap<String,List<MappingModuleEntry>>();
      for(MappingModuleEntry entry : authInfo.getModuleEntries())
      {
         String type = entry.getMappingModuleType();
         if(mappings.containsKey(type))
            mappings.get(type).add(entry);
         else
         {
            List<MappingModuleEntry> entries = new ArrayList<MappingModuleEntry>();
            entries.add(entry);
            mappings.put(type, entries);
         }
      }
      // now set all mapping infos by type.
      for(Map.Entry<String,List<MappingModuleEntry>> entry : mappings.entrySet())
      {
         MappingInfo info = new MappingInfo(authInfo.getName());
         info.add(entry.getValue());
         aPolicy.setMappingInfo(entry.getKey(), info);
      }
      if (trace)
         log.trace("addChild.ApplicationPolicy, name: " + aPolicy.getName());
   }

   public void addChild(MappingModuleEntry entry, ModuleOption option, UnmarshallingContext navigator,
         String namespaceURI, String localName)
   {
      entry.add(option);
      if (trace)
         log.trace("addChild.MappingModuleEntry, name: " + option.getName());
   }

   public void addChild(MappingInfo authInfo, MappingModuleEntry entry, UnmarshallingContext navigator,
         String namespaceURI, String localName)
   {
      authInfo.add(entry);
   }

   // Audit Info
   public Object newChild(AuditInfo info, UnmarshallingContext navigator, String namespaceUri, String localName,
         Attributes attrs)
   {
      Object child = null;
      if (trace)
         log.trace("newChild.AuditInfo, localName: " + localName);
      if ("provider-module".equals(localName))
      {
         String code = attrs.getValue("code");
         code = StringPropertyReplacer.replaceProperties(code.trim());
         AuditProviderEntry entry = new AuditProviderEntry(code);
         child = entry;
         if (trace)
            log.trace("newChild.AuditInfo, provider-module code: " + code);
      }

      return child;
   }

   public Object newChild(AuditProviderEntry entry, UnmarshallingContext navigator, String namespaceUri,
         String localName, Attributes attrs)
   {
      Object child = null;
      if (trace)
         log.trace("newChild.AuditProviderEntry, localName: " + localName);
      if ("module-option".equals(localName))
      {
         String name = attrs.getValue("name");
         child = new ModuleOption(name);
         if (trace)
            log.trace("newChild.AuditProviderEntry, module-option name: " + name);
      }

      return child;
   }

   public void addChild(ApplicationPolicy aPolicy, AuditInfo auditInfo, UnmarshallingContext navigator,
         String namespaceURI, String localName)
   {
      aPolicy.setAuditInfo(auditInfo);
      if (trace)
         log.trace("addChild.ApplicationPolicy, name: " + aPolicy.getName());
   }

   public void addChild(AuditProviderEntry entry, ModuleOption option, UnmarshallingContext navigator,
         String namespaceURI, String localName)
   {
      entry.add(option);
      if (trace)
         log.trace("addChild.MappingModuleEntry, name: " + option.getName());
   }

   public void addChild(AuditInfo auditInfo, AuditProviderEntry entry, UnmarshallingContext navigator,
         String namespaceURI, String localName)
   {
      auditInfo.add(entry);
   }

   // Identity Trust
   public Object newChild(IdentityTrustInfo info, UnmarshallingContext navigator, String namespaceUri,
         String localName, Attributes attrs)
   {
      Object child = null;
      if (trace)
         log.trace("newChild.IdentityTrustInfo, localName: " + localName);
      if ("trust-module".equals(localName))
      {
         String code = attrs.getValue("code");
         code = StringPropertyReplacer.replaceProperties(code.trim());

         String flag = attrs.getValue("flag");
         if (flag == null)
            flag = "REQUIRED";
         flag = StringPropertyReplacer.replaceProperties(flag.trim());

         ControlFlag controlFlag = this.controlFlags.get(flag.toUpperCase());
         if (controlFlag == null)
            controlFlag = ControlFlag.REQUIRED;

         IdentityTrustModuleEntry entry = new IdentityTrustModuleEntry(code);
         entry.setControlFlag(controlFlag);

         child = entry;
         if (trace)
            log.trace("newChild.IdentityTrustInfo, trust-module code: " + code);
      }

      return child;
   }

   public Object newChild(IdentityTrustModuleEntry entry, UnmarshallingContext navigator, String namespaceUri,
         String localName, Attributes attrs)
   {
      Object child = null;
      if (trace)
         log.trace("newChild.trustProviderEntry, localName: " + localName);
      if ("module-option".equals(localName))
      {
         String name = attrs.getValue("name");
         child = new ModuleOption(name);
         if (trace)
            log.trace("newChild.trustProviderEntry, module-option name: " + name);
      }

      return child;
   }

   public void addChild(ApplicationPolicy aPolicy, IdentityTrustInfo auditInfo, UnmarshallingContext navigator,
         String namespaceURI, String localName)
   {
      aPolicy.setIdentityTrustInfo(auditInfo);
      if (trace)
         log.trace("addChild.ApplicationPolicy, name: " + aPolicy.getName());
   }

   public void addChild(IdentityTrustModuleEntry entry, ModuleOption option, UnmarshallingContext navigator,
         String namespaceURI, String localName)
   {
      entry.add(option);
      if (trace)
         log.trace("addChild.MappingModuleEntry, name: " + option.getName());
   }

   public void addChild(IdentityTrustInfo auditInfo, IdentityTrustModuleEntry entry, UnmarshallingContext navigator,
         String namespaceURI, String localName)
   {
      auditInfo.add(entry);
   }
}
