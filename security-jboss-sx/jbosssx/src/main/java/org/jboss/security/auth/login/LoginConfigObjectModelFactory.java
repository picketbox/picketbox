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
package org.jboss.security.auth.login;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;

import org.jboss.logging.Logger;
import org.jboss.security.auth.container.config.AuthModuleEntry;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.ControlFlag;
import org.jboss.security.config.ModuleOption;
import org.jboss.security.config.PolicyConfig;
import org.jboss.util.StringPropertyReplacer;
import org.jboss.xb.binding.ObjectModelFactory;
import org.jboss.xb.binding.UnmarshallingContext;
import org.xml.sax.Attributes;

/**
 * A JBossXB object factory for parsing the login-config.xml object model.
 * 
 * @author Scott.Stark@jboss.org
 * @author <a href="mailto:Anil.Saldhana@jboss.org">Anil.Saldhana@jboss.org</a>
 * @version $Revision$
 */
public class LoginConfigObjectModelFactory implements ObjectModelFactory
{
   private static Logger log = Logger.getLogger(LoginConfigObjectModelFactory.class);

   private boolean trace;
   
   protected final Map<String, ControlFlag> controlFlags;

   public LoginConfigObjectModelFactory()
   { 
      this.controlFlags = new HashMap<String, ControlFlag>();
      controlFlags.put("REQUIRED", ControlFlag.REQUIRED);
      controlFlags.put("REQUISITE", ControlFlag.REQUISITE);
      controlFlags.put("OPTIONAL", ControlFlag.OPTIONAL);
      controlFlags.put("SUFFICIENT", ControlFlag.SUFFICIENT);
   }

   public Object completeRoot(Object root, UnmarshallingContext ctx, String uri, String name)
   {
      if (trace)
         log.trace("completeRoot");
      return root;
   }

   public Object newRoot(Object root, UnmarshallingContext navigator, String namespaceURI, String localName,
         Attributes attrs)
   {
      trace = log.isTraceEnabled();
      if (!localName.equals("policy"))
      {
         throw new IllegalStateException("Unexpected root element: was expecting 'policy' but got '" + localName + "'");
      }
      if (trace)
         log.trace("newRoot, created PolicyConfig for policy element");
      return new PolicyConfig();
   }

   public Object newChild(PolicyConfig config, UnmarshallingContext navigator, String namespaceUri, String localName,
         Attributes attrs)
   {
      Object child = null;
      if (trace)
         log.trace("newChild.PolicyConfig, localName: " + localName);
      if ("application-policy".equals(localName))
      {
         String name = attrs.getValue("name");
         name = StringPropertyReplacer.replaceProperties(name);
         ApplicationPolicy aPolicy = new ApplicationPolicy(name);
         aPolicy.setPolicyConfig(config);
         String baseAppPolicyName = attrs.getValue("extends");
         if (baseAppPolicyName != null)
            aPolicy.setBaseApplicationPolicyName(baseAppPolicyName);
         if (trace)
            log.trace("newChild.PolicyConfig, AuthenticationInfo: " + name);
         child = aPolicy;
      }
      return child;
   }

   public Object newChild(ApplicationPolicy aPolicy, UnmarshallingContext navigator, String namespaceUri,
         String localName, Attributes attrs)
   {
      Object child = null;
      if (trace)
         log.trace("newChild.ApplicationPolicy, localName: " + localName);
      String name = aPolicy.getName();
      if ("authentication".equals(localName))
      {
         child = new AuthenticationInfo(name);
         if (trace)
            log.trace("newChild.PolicyConfig, AuthenticationInfo: " + name);
      }
      else if ("authentication-jaspi".equals(localName))
      {
         child = new JASPIAuthenticationInfo(name);
         if (trace)
            log.trace("newChild.PolicyConfig, AuthenticationInfo: " + name);
      }
      return child;
   }

   public Object newChild(BaseAuthenticationInfo info, UnmarshallingContext navigator, String namespaceUri,
         String localName, Attributes attrs)
   {
      Object child = null;
      if (trace)
         log.trace("newChild.AuthenticationInfo, localName: " + localName);
      if ("authentication".equals(localName))
      {
         child = new AuthenticationInfo(info.getName());
         if (trace)
            log.trace("newChild.PolicyConfig, AuthenticationInfo: " + info.getName());
      }
      else if ("authentication-jaspi".equals(localName))
      {
         child = new JASPIAuthenticationInfo(info.getName());
         if (trace)
            log.trace("newChild.PolicyConfig, AuthenticationInfo: " + info.getName());
      }
      return child;
   }

   public Object newChild(AuthenticationInfo info, UnmarshallingContext navigator, String namespaceUri,
         String localName, Attributes attrs)
   {
      Object child = null;
      if (trace)
         log.trace("newChild.AuthenticationInfo, localName: " + localName);
      if ("login-module".equals(localName))
      {
         String code = attrs.getValue("code");
         code = StringPropertyReplacer.replaceProperties(code.trim());
         String flag = attrs.getValue("flag");
         if (flag != null)
            flag = StringPropertyReplacer.replaceProperties(flag.trim());
         AppConfigurationEntryHolder holder = new AppConfigurationEntryHolder(code, flag);
         child = holder;
         if (trace)
            log.trace("newChild.AuthenticationInfo, login-module code: " + code);
      }

      return child;
   }

   public Object newChild(JASPIAuthenticationInfo info, UnmarshallingContext navigator, String namespaceUri,
         String localName, Attributes attrs)
   {
      Object child = null;
      if (trace)
         log.trace("newChild.AuthenticationJaspiInfo, localName: " + localName);
      if ("login-module-stack".equals(localName))
      {
         String lmsName = attrs.getValue("name");
         lmsName = StringPropertyReplacer.replaceProperties(lmsName.trim());
         child = new LoginModuleStackHolder(lmsName, null);
         if (trace)
            log.trace("newChild.AuthenticationInfo, login-module-stack: " + lmsName);
      }
      else if ("auth-module".equals(localName))
      {
         String code = attrs.getValue("code");
         AuthModuleEntry authModuleEntry = new AuthModuleEntry(code, null, null);
         
         String flag = attrs.getValue("flag"); 
         authModuleEntry.setControlFlag(getControlFlag(flag));
         
         String lmsRef = attrs.getValue("login-module-stack-ref");
         if (lmsRef != null)
            authModuleEntry.setLoginModuleStackHolder(info.getLoginModuleStackHolder(lmsRef));
         child = authModuleEntry;
      }

      return child;
   }

   public Object newChild(LoginModuleStackHolder entry, UnmarshallingContext navigator, String namespaceUri,
         String localName, Attributes attrs)
   {
      Object child = null;
      if (trace)
         log.trace("newChild.LoginModuleStackHolder, localName: " + localName);
      if ("login-module".equals(localName))
      {
         String code = attrs.getValue("code");
         code = StringPropertyReplacer.replaceProperties(code.trim());
         String flag = attrs.getValue("flag");
         flag = StringPropertyReplacer.replaceProperties(flag.trim());
         AppConfigurationEntryHolder holder = new AppConfigurationEntryHolder(code, flag);
         child = holder;
         if (trace)
            log.trace("newChild.AuthenticationInfo, login-module code: " + code);
      }

      return child;
   }

   public Object newChild(AppConfigurationEntryHolder entry, UnmarshallingContext navigator, String namespaceUri,
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
            log.trace("newChild.AppConfigurationEntryHolder, module-option name: " + name);
      }

      return child;
   }

   public Object newChild(AuthModuleEntry entry, UnmarshallingContext navigator, String namespaceUri, String localName,
         Attributes attrs)
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

   public void setValue(ModuleOption option, UnmarshallingContext navigator, String namespaceUri, String localName,
         String value)
   {
      if ("module-option".equals(localName))
      {
         String valueWithReplacement = StringPropertyReplacer.replaceProperties(value.trim());
         option.setValue(valueWithReplacement);
         if (trace)
            log.trace("setValue.ModuleOption, name: " + localName + ":valueWithReplacement:" + valueWithReplacement);
      }
   }

   public void addChild(ModuleOption option, Object value, UnmarshallingContext navigator, String namespaceURI,
         String localName)
   {
      option.setValue(value);
      if (trace)
         log.trace("addChild.ModuleOption, name: " + option.getName());
   }

   public void addChild(AuthenticationInfo authInfo, AppConfigurationEntryHolder entryInfo,
         UnmarshallingContext navigator, String namespaceURI, String localName)
   {
      AppConfigurationEntry entry = entryInfo.getEntry();
      authInfo.addAppConfigurationEntry(entry);
      if (trace)
         log.trace("addChild.AuthenticationInfo, name: " + entry.getLoginModuleName());
   }

   public void addChild(AppConfigurationEntryHolder entryInfo, ModuleOption option, UnmarshallingContext navigator,
         String namespaceURI, String localName)
   {
      entryInfo.addOption(option);
      if (trace)
         log.trace("addChild.AppConfigurationEntryHolder, name: " + option.getName());
   }

   public void addChild(JASPIAuthenticationInfo authInfo, AuthModuleEntry entry, UnmarshallingContext navigator,
         String namespaceURI, String localName)
   {
      authInfo.add(entry);
   }

   public void addChild(LoginModuleStackHolder lmsh, AppConfigurationEntryHolder entryInfo,
         UnmarshallingContext navigator, String namespaceURI, String localName)
   {
      lmsh.addAppConfigurationEntry(entryInfo.getEntry());
      if (trace)
         log.trace("addChild.LoginModuleStackHolder, name: " + entryInfo.getEntry().getLoginModuleName());
   }

   public void addChild(AuthModuleEntry entry, ModuleOption option, UnmarshallingContext navigator,
         String namespaceURI, String localName)
   {
      entry.addOption(option);
      if (trace)
         log.trace("addChild.AppConfigurationEntryHolder, name: " + option.getName());
   }

   public void addChild(JASPIAuthenticationInfo authInfo, LoginModuleStackHolder lmsHolder,
         UnmarshallingContext navigator, String namespaceURI, String localName)
   {
      authInfo.add(lmsHolder);
   }

   public void addChild(ApplicationPolicy aPolicy, JASPIAuthenticationInfo authInfo, UnmarshallingContext navigator,
         String namespaceURI, String localName)
   {
      aPolicy.setAuthenticationInfo(authInfo);
      if (trace)
         log.trace("addChild.ApplicationPolicy, name: " + aPolicy.getName());
   }

   public void addChild(ApplicationPolicy aPolicy, AuthenticationInfo authInfo, UnmarshallingContext navigator,
         String namespaceURI, String localName)
   {
      aPolicy.setAuthenticationInfo(authInfo);
      if (trace)
         log.trace("addChild.ApplicationPolicy, name: " + aPolicy.getName());
   }

   public void addChild(PolicyConfig pc, ApplicationPolicy aPolicy, UnmarshallingContext navigator,
         String namespaceURI, String localName)
   {
      pc.add(aPolicy);
      if (trace)
         log.trace("Added ApplicationPolicy to PolicyConfig, name: " + aPolicy.getName());
   }
   
   public ControlFlag getControlFlag(String flag)
   {
      ControlFlag controlFlag = null;
      
      if(flag != null)
      {
         flag = StringPropertyReplacer.replaceProperties(flag.trim());
         controlFlag = this.controlFlags.get(flag.toUpperCase()); 
      }
      if (controlFlag == null)
         controlFlag = ControlFlag.REQUIRED;
      
      return controlFlag;
   }

}