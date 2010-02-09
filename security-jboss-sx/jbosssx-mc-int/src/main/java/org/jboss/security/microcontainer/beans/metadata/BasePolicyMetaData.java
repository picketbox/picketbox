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

import org.jboss.beans.metadata.spi.BeanMetaData;
import org.jboss.beans.metadata.spi.ValueMetaData;
import org.jboss.beans.metadata.spi.builder.BeanMetaDataBuilder;

/**
 * <p>
 * Superclass of all policies that form an application-policy. It defines the metadata common to all policies.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class BasePolicyMetaData
{
   /** the collection of the modules specified for the policy. */
   protected List<BaseModuleMetaData> modules;

   /**
    * <p>
    * Obtains the metadata of the modules that have been specified for the policy.
    * </p>
    * 
    * @return a {@code List<BaseModuleMetaData>} containing the metadata of the modules.
    */
   public List<BaseModuleMetaData> getModules()
   {
      return modules;
   }

   /**
    * <p>
    * Sets the metadata of the modules that have been specified for the policy.
    * </p>
    * 
    * @param modules a {@code List<BaseModuleMetaData>} containing the metadata to be set.
    */
   public void setModules(List<BaseModuleMetaData> modules)
   {
      this.modules = modules;
   }

   /**
    * <p>
    * Creates the {@code BeanMetaData} objects that will be used by the microcontainer to create and populate an
    * instance of the policy bean.
    * </p>
    * 
    * @param policyName the name of the policy bean to be created.
    * @param beanClass the class name of the policy bean.
    * @return a {@code List} containing all {@code BeanMetaData} objects needed to create the policy bean and its
    *         modules.
    */
   public List<BeanMetaData> getBeans(String policyName, String beanClass)
   {
      // create the metadata for the policy bean.
      List<BeanMetaData> result = new ArrayList<BeanMetaData>();
      BeanMetaDataBuilder builder = BeanMetaDataBuilder.createBuilder(policyName, beanClass);
      result.add(builder.getBeanMetaData());

      if (this.modules != null)
      {
         // if there are modules defined, add their metadata to the result.
         int moduleIndex = 0;
         List<ValueMetaData> modulesMetaData = builder.createList();
         for (BaseModuleMetaData moduleMetaData : this.modules)
         {
            String moduleName = policyName + "$Module" + moduleIndex++;
            result.add(moduleMetaData.getBean(moduleName));
            // inject the module into the collection of modules metadata.
            ValueMetaData injectLoginModule = builder.createInject(moduleName);
            modulesMetaData.add(injectLoginModule);
         }
         // inject the collection of modules into the policy bean.
         builder.addPropertyMetaData("modules", modulesMetaData);
      }

      // give subclasses a chance to add policy-specific metadata information to the result.
      this.addBeans(policyName, result, builder);

      return result;
   }

   /**
    * <p>
    * This method allows subclasses to add policy-specific metadata to the collection of {@code BeanMetaData} that is
    * constructed by the {@code getBeans(String, String)} method.
    * </p>
    * 
    * @param policyName the name of the policy bean to be created.
    * @param beans the collection of {@code BeanMetaData} objects that has been created and populated by the
    *            {@code getBeans} method.
    * @param builder the {@code BeanMetaDataBuilder} used to create the {@code BeanMetaData} objects.
    * @see #getBeans(String, String)
    */
   public void addBeans(String policyName, List<BeanMetaData> beans, BeanMetaDataBuilder builder)
   {
   }
}
