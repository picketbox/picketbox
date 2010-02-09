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

import org.jboss.beans.metadata.spi.BeanMetaData;
import org.jboss.beans.metadata.spi.ValueMetaData;
import org.jboss.beans.metadata.spi.builder.BeanMetaDataBuilder;
import org.jboss.security.microcontainer.beans.LoginModuleStackBean;

/**
 * <p>
 * This class contains the metadata of a stack of login modules.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class LoginModuleStackMetaData
{

   /** the name of the login module stack. */
   private String name;

   /** the metadata of the stack modules. */
   private List<FlaggedModuleMetaData> loginModules;

   /**
    * <p>
    * Obtains the name of the login module stack.
    * </p>
    * 
    * @return a {@code String} containing the name of the stack.
    */
   public String getName()
   {
      return name;
   }

   /**
    * <p>
    * Sets the name of the login module stack.
    * </p>
    * 
    * @param name a {@code String} containing the name to be set.
    */
   @XmlAttribute
   public void setName(String name)
   {
      this.name = name;
   }

   /**
    * <p>
    * Obtains the metadata of the stack modules.
    * </p>
    * 
    * @return a {@code List} containing the metadata of the stack modules.
    */
   public List<FlaggedModuleMetaData> getLoginModules()
   {
      return loginModules;
   }

   /**
    * <p>
    * Sets the stack modules metadata.
    * </p>
    * 
    * @param loginModules a {@code List} containing the metadata to be set.
    */
   @XmlElement(name = "login-module", type = FlaggedModuleMetaData.class)
   public void setLoginModules(List<FlaggedModuleMetaData> loginModules)
   {
      this.loginModules = loginModules;
   }

   /**
    * <p>
    * Creates the {@code BeanMetaData} objects that will be used by the microcontainer to create and populate an
    * instance of {@code LoginModuleStackBean}.
    * </p>
    * 
    * @param stackName the name of the {@code LoginModuleStackBean} to be created.
    * @return a {@code List} containing all {@code BeanMetaData} objects needed to create the bean and its modules.
    */
   public List<BeanMetaData> getBeans(String stackName)
   {
      // create the metadata for the LoginModuleStackBean.
      List<BeanMetaData> result = new ArrayList<BeanMetaData>();
      BeanMetaDataBuilder builder = BeanMetaDataBuilder.createBuilder(stackName, LoginModuleStackBean.class.getName());
      builder.addPropertyMetaData("name", this.name);
      result.add(builder.getBeanMetaData());

      if (this.loginModules != null)
      {
         // if there are modules, create their metadata and inject them into the stack metadata.
         int moduleIndex = 0;
         List<ValueMetaData> modulesMetaData = builder.createList();
         for (BaseModuleMetaData moduleMetaData : this.loginModules)
         {
            String loginModuleName = stackName + "$Module" + moduleIndex++;
            // create the module metadata.
            result.add(moduleMetaData.getBean(loginModuleName));
            ValueMetaData injectLoginModule = builder.createInject(loginModuleName);
            modulesMetaData.add(injectLoginModule);
         }
         // inject all modules into the stack metadata.
         builder.addPropertyMetaData("loginModules", modulesMetaData);
      }

      return result;
   }
}
