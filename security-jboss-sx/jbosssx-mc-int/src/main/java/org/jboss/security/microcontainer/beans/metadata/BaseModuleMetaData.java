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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;

import org.jboss.beans.metadata.spi.BeanMetaData;
import org.jboss.beans.metadata.spi.builder.BeanMetaDataBuilder;
import org.jboss.security.microcontainer.beans.BasePolicyModule;

/**
 * <p>
 * This class contains the metadata of a simple policy module.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class BaseModuleMetaData
{
   /** the fully-qualified class name of the module. */
   protected String code;

   /** the module options metadata. */
   protected List<ModuleOptionMetaData> moduleOptions;

   /**
    * <p>
    * Obtains the fully-qualified class name of the module.
    * </p>
    * 
    * @return a {@code String} containing the module's class name.
    */
   public String getCode()
   {
      return code;
   }

   /**
    * <p>
    * Sets the fully-qualified class name of the module.
    * </p>
    * 
    * @param code a {@code String} containing the class name to be set.
    */
   @XmlAttribute(required = true)
   public void setCode(String code)
   {
      this.code = code;
   }

   /**
    * <p>
    * Obtains the metadata of the module options.
    * </p>
    * 
    * @return a {@code List<ModuleOptionMetaData>} containing the option's metadata.
    */
   public List<ModuleOptionMetaData> getModuleOptions()
   {
      return moduleOptions;
   }

   /**
    * <p>
    * Sets the metadata of the module options.
    * </p>
    * 
    * @param moduleOptions a {@code List<ModuleOptionMetaData>} containing the metadata to be set.
    */
   @XmlElement(name = "module-option", type = ModuleOptionMetaData.class)
   public void setModuleOptions(List<ModuleOptionMetaData> moduleOptions)
   {
      this.moduleOptions = moduleOptions;
   }

   /**
    * <p>
    * the {@code BeanMetaData} object that will be used by the microcontainer to create and populate an instance of
    * {@code BasePolicyModule}.
    * </p>
    * 
    * @param moduleName the name of the module bean to be created.
    * @return a {@code BeanMetaData} object containing the metadata needed to create the module bean.
    */
   public BeanMetaData getBean(String moduleName)
   {
      // create the metadata for the module bean.
      BeanMetaDataBuilder moduleBuilder = BeanMetaDataBuilder.createBuilder(moduleName, BasePolicyModule.class
            .getName());
      moduleBuilder.addPropertyMetaData("code", this.code);

      // add the options map to the metadata.
      if (this.moduleOptions != null)
      {
         Map<String, String> optionsMap = new HashMap<String, String>();
         for (ModuleOptionMetaData optionMetaData : this.moduleOptions)
            optionsMap.put(optionMetaData.getName(), optionMetaData.getValue());
         moduleBuilder.addPropertyMetaData("options", optionsMap);
      }

      return moduleBuilder.getBeanMetaData();
   }

}
