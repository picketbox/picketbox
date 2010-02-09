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

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlValue;

/**
 * <p>
 * This class contains the metadata of a module option.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class ModuleOptionMetaData
{
   /** the name of the option. */
   private String name;

   /** the value of the option. */
   private String value;

   /**
    * <p>
    * Obtains the name of the option.
    * </p>
    * 
    * @return a {@code String} representing the option's name.
    */
   public String getName()
   {
      return name;
   }

   /**
    * <p>
    * Sets the name of the option.
    * </p>
    * 
    * @param name a {@code String} representing the name to be set.
    */
   @XmlAttribute(required = true)
   public void setName(String name)
   {
      this.name = name;
   }

   /**
    * <p>
    * Obtains the value of the option.
    * </p>
    * 
    * @return a {@code String} representing the option's value.
    */
   public String getValue()
   {
      return value;
   }

   /**
    * <p>
    * Sets the value of the option.
    * </p>
    * 
    * @param value {@code String} representing the value to be set.
    */
   @XmlValue
   public void setValue(String value)
   {
      this.value = value;
   }

}
