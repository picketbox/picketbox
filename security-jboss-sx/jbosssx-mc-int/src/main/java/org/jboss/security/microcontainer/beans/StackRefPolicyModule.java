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

import java.util.Map;

/**
 * <p>
 * This class represents a policy module that contains a reference to a login-module stack configured in a JASPI policy.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class StackRefPolicyModule extends BasePolicyModule
{

   /** the name of the login-module stack referenced by the module. */
   private String stackRef;

   /**
    * <p>
    * Obtains the name of the login-module stack referenced by the module.
    * </p>
    * 
    * @return a {@code String} representing the name of the login-module stack.
    */
   public String getStackRef()
   {
      return stackRef;
   }

   /**
    * <p>
    * Sets the name of the login-module stack referenced by the module.
    * </p>
    * 
    * @param stackRef a {@code String} representing the name of the login-module stack.
    */
   public void setStackRef(String stackRef)
   {
      this.stackRef = stackRef;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.microcontainer.beans.BasePolicyModule#toString()
    */
   @Override
   public String toString()
   {
      StringBuffer buffer = new StringBuffer();
      buffer.append("Login module class: " + super.code);
      buffer.append("\nLogin module stack-ref: " + this.stackRef);
      buffer.append("\nLogin module options: \n");
      for (Map.Entry<String, Object> entry : super.options.entrySet())
         buffer.append("\tname= " + entry.getKey() + ", value= " + entry.getValue() + "\n");
      return buffer.toString();
   }
}
