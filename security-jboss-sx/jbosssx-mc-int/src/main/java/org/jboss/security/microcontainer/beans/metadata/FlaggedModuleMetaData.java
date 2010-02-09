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
import java.util.Map;

import javax.xml.bind.annotation.XmlAttribute;

import org.jboss.beans.metadata.spi.BeanMetaData;
import org.jboss.beans.metadata.spi.builder.BeanMetaDataBuilder;
import org.jboss.security.microcontainer.beans.FlaggedPolicyModule;

/**
 * <p>
 * This class extends the {@code BaseModuleMetaData} to add the metadata needed to build a {@code FlaggedPolicyModule}.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class FlaggedModuleMetaData extends BaseModuleMetaData
{

   /** the flag (required, requisite, sufficient, optional) of the module. */
   private String flag;

   /**
    * <p>
    * Obtains the flag of the module.
    * </p>
    * 
    * @return a {@code String} representing the module's flag.
    */
   public String getFlag()
   {
      return flag;
   }

   /**
    * <p>
    * Sets the flag of the module.
    * </p>
    * 
    * @param flag a {@code String} representing the flag to be set.
    */
   @XmlAttribute(required = true)
   public void setFlag(String flag)
   {
      this.flag = flag;
   }

   /**
    * <p>
    * Overrides the superclass method to create a {@code BeanMetaDataObject} that will be used by the microcontainer to
    * generate an instance of {@code FlaggedPolicyModule}.
    * </p>
    */
   @Override
   public BeanMetaData getBean(String moduleName)
   {
      // create the metadata for the module bean.
      BeanMetaDataBuilder moduleBuilder = BeanMetaDataBuilder.createBuilder(moduleName, FlaggedPolicyModule.class
            .getName());
      moduleBuilder.addPropertyMetaData("code", this.code);
      moduleBuilder.addPropertyMetaData("flag", this.flag);

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