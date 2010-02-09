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
package org.jboss.security.microcontainer.beans;

import java.util.HashMap;
import java.util.Map;

/**
 * <p>
 * This bean represents a basic policy module, with its class name and options map.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class BasePolicyModule
{

   /** the fully-qualified name of the module. */
   protected String code;

   /** The module's options map (name -> value). */
   protected Map<String, Object> options;

   /**
    * <p>
    * Creates an instance of {@code BasePolicyModule}.
    * </p>
    */
   public BasePolicyModule()
   {
      this.options = new HashMap<String, Object>();
   }

   /**
    * <p>
    * Obtains the fully-qualified class name of the module.
    * </p>
    * 
    * @return a {@code String} representing the class name.
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
    * @param code a {@code String} representing the class name to be set.
    */
   public void setCode(String code)
   {
      this.code = code;
   }

   /**
    * <p>
    * Obtains the module's options.
    * </p>
    * 
    * @return a {@code Map<String,Object>} containing the module's options.
    */
   public Map<String, Object> getOptions()
   {
      return options;
   }

   /**
    * <p>
    * Sets the options of the module.
    * </p>
    * 
    * @param options a {@code Map<String,Object>} containing the options to be set.
    */
   public void setOptions(Map<String, Object> options)
   {
      this.options = options;
   }

   /*
    * (non-Javadoc)
    * 
    * @see java.lang.Object#toString()
    */
   @Override
   public String toString()
   {
      StringBuffer buffer = new StringBuffer();
      buffer.append("Login module class: " + this.code);
      buffer.append("\nLogin module options: \n");
      for (Map.Entry<String, Object> entry : this.options.entrySet())
         buffer.append("\tname= " + entry.getKey() + ", value= " + entry.getValue() + "\n");
      return buffer.toString();
   }
}
