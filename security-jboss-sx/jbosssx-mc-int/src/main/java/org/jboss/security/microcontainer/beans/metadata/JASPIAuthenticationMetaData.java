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

import java.util.List;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

import org.jboss.beans.metadata.spi.BeanMetaData;
import org.jboss.beans.metadata.spi.ValueMetaData;
import org.jboss.beans.metadata.spi.builder.BeanMetaDataBuilder;

/**
 * <p>
 * This class represents the {@code <authentication-jaspi>} configuration in an application policy and contains the
 * jaspi authentication metadata information extracted by the XB parser.
 * </p>
 * <p>
 * The following policy excerpt shows an example of {@code <authentication-jaspi>} configuration:
 * 
 * <pre>
 *  &lt;application-policy xmlns=&quot;urn:jboss:security-beans:1.0&quot; name=&quot;TestPolicy1&quot;&gt;
 *     &lt;authentication-jaspi&gt;
 *        &lt;login-module-stack name=&quot;ModuleStack1&quot;&gt;
 *           &lt;login-module code=&quot;org.jboss.security.auth.StackModule1&quot; flag=&quot;required&quot;&gt;
 *              &lt;module-option name=&quot;stackOption1&quot;&gt;stack1.value1&lt;/module-option&gt;
 *           &lt;/login-module&gt;
 *           &lt;login-module code=&quot;org.jboss.security.auth.StackModule2&quot; flag=&quot;option&quot;/&gt;
 *        &lt;/login-module-stack&gt;
 *        &lt;login-module-stack name=&quot;ModuleStack2&quot;&gt;
 *           &lt;login-module code=&quot;org.jboss.security.auth.StackModule1&quot; flag=&quot;required&quot;&gt;
 *              &lt;module-option name=&quot;stackOption1&quot;&gt;stack2.value1&lt;/module-option&gt;
 *              &lt;module-option name=&quot;stackOption2&quot;&gt;stack2.value2&lt;/module-option&gt;
 *           &lt;/login-module&gt;
 *        &lt;/login-module-stack&gt;
 *        &lt;auth-module code=&quot;org.jboss.security.auth.AuthModule&quot; login-module-stack-ref=&quot;ModuleStack1&quot;&gt;
 *           &lt;module-option name=&quot;authOption1&quot;&gt;auth.value1&lt;/module-option&gt;
 *           &lt;module-option name=&quot;authOption2&quot;&gt;auth.value2&lt;/module-option&gt;
 *        &lt;/auth-module&gt;
 *     &lt;/authentication-jaspi&gt;
 *  ...
 *  &lt;/application-policy&gt;
 * </pre>
 * 
 * The metadata that results from the XB parsing is used by the microcontainer to create an instance of
 * {@code JASPIAuthenticationPolicyBean} and inject this instance into the {@code ApplicationPolicyBean} that represents
 * the application policy as a whole.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
@XmlType(name = "authenticationJaspiType", propOrder = {"moduleStacks", "modules"})
public class JASPIAuthenticationMetaData extends BasePolicyMetaData
{

   /** the collection of module stacks of the jaspi policy. */
   private List<LoginModuleStackMetaData> moduleStacks;

   /**
    * <p>
    * Obtains the metadata of the module stacks.
    * </p>
    * 
    * @return a {@code List<LoginModuleStackMetaData>} containing the module stacks metadata.
    */
   public List<LoginModuleStackMetaData> getModuleStacks()
   {
      return moduleStacks;
   }

   /**
    * <p>
    * Sets the metadata of the module stacks.
    * </p>
    * 
    * @param moduleStacks a {@code List<LoginModuleStackMetaData>} containing the metadata to be set.
    */
   @XmlElement(name = "login-module-stack", type = LoginModuleStackMetaData.class)
   public void setModuleStacks(List<LoginModuleStackMetaData> moduleStacks)
   {
      this.moduleStacks = moduleStacks;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.microcontainer.beans.metadata.BasePolicyMetaData#setModules(java.util.List)
    */
   @Override
   @XmlElement(name = "auth-module", type = StackRefModuleMetaData.class)
   public void setModules(List<BaseModuleMetaData> modules)
   {
      super.modules = modules;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.microcontainer.beans.metadata.BasePolicyMetaData#addBeans(java.lang.String,
    *      java.util.List, org.jboss.beans.metadata.spi.builder.BeanMetaDataBuilder)
    */
   @Override
   public void addBeans(String policyName, List<BeanMetaData> beans, BeanMetaDataBuilder builder)
   {
      if (this.moduleStacks != null)
      {
         // if there are stacks of login modules, add them to the jaspi policy metadata being created.
         int stackIndex = 0;
         List<ValueMetaData> stackMetaData = builder.createList();
         for (LoginModuleStackMetaData moduleStack : this.moduleStacks)
         {
            String moduleStackName = policyName + "$ModuleStack" + stackIndex++;
            beans.addAll(moduleStack.getBeans(moduleStackName));
            ValueMetaData injectModuleStack = builder.createInject(moduleStackName);
            stackMetaData.add(injectModuleStack);
         }
         builder.addPropertyMetaData("moduleStacks", stackMetaData);
      }
   }

}
