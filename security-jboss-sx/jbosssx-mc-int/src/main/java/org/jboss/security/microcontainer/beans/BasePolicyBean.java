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

import java.util.ArrayList;
import java.util.List;

/**
 * <p>
 * Superclass of all policy beans that compose an {@code ApplicationPolicyBean}.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * 
 * @param <M> the type of the modules used by the policy.
 * @param <I> the type of the info object that the policy is capable of generating.
 */
public abstract class BasePolicyBean<M, I>
{

   /** the policy's set of modules. */
   protected List<M> modules;

   /**
    * <p>
    * Creates an instance of {@code BasePolicyBean}.
    * </p>
    */
   public BasePolicyBean()
   {
      this.modules = new ArrayList<M>();
   }

   /**
    * <p>
    * Gets a reference to collection of modules used by this policy.
    * </p>
    * 
    * @return a reference to the {@code List} that contains the policy's modules.
    */
   public List<M> getModules()
   {
      return modules;
   }

   /**
    * <p>
    * Sets the collection of modules used by this policy.
    * </p>
    * 
    * @param modules a {@code List} containing all modules to be used by this policy.
    */
   public void setModules(List<M> modules)
   {
      this.modules = modules;
   }

   /**
    * <p>
    * Creates a security info object using the information contained in this policy bean.
    * </p>
    * 
    * @param domainName a {@code String} containing the security domain name of this policy.
    * @return the generated info object.
    */
   public abstract I getPolicyInfo(String domainName);

}
