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
package org.jboss.test.security.acl;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import javax.persistence.Id;

import org.jboss.security.authorization.Resource;
import org.jboss.security.authorization.ResourceType;

/**
 * <p>
 * A simple {@code Resource} implementation for testing purposes.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class TestResource implements Resource, Serializable
{

   private static final long serialVersionUID = -3581842532933324293L;

   @Id
   private final int resourceId;

   private String name;

   private final Map<String, Object> contextMap;

   /**
    * <p>
    * Creates an instance of {@code TestResource} with the specified id.
    * </p>
    * 
    * @param resourceId an {@code int} representing the id of the resource.
    */
   public TestResource(int resourceId)
   {
      this(resourceId, null);
   }

   /**
    * <p>
    * Creates an instance of {@code TestResource} with the specified id and name.
    * </p>
    * 
    * @param resourceId an {@code int} representing the id of the resource.
    * @param resourceName a {@code String} representing the name of the resource.
    */
   public TestResource(int resourceId, String resourceName)
   {
      this.resourceId = resourceId;
      this.name = resourceName;
      this.contextMap = new HashMap<String, Object>();
   }

   /**
    * <p>
    * Gets the id of this resource.
    * </p>
    * 
    * @return an {@code int} representing the id of this resource.
    */
   public int getResourceId()
   {
      return this.resourceId;
   }

   /**
    * <p>
    * Gets the name of this resource.
    * </p>
    * 
    * @return a {@code String} representing the name of this resource.
    */
   public String getResourceName()
   {
      return this.name;
   }

   /**
    * <p>
    * Defines the name of this resource.
    * </p>
    * 
    * @param name a {@code String} containing the name to be set.
    */
   public void setResourceName(String name)
   {
      this.name = name;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.authorization.Resource#getLayer()
    */
   public ResourceType getLayer()
   {
      return ResourceType.ACL;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.authorization.Resource#getMap()
    */
   public Map<String, Object> getMap()
   {
      return this.contextMap;
   }

   @Override
   public boolean equals(Object obj)
   {
      if (obj instanceof TestResource)
         return this.resourceId == ((TestResource) obj).resourceId;
      return false;
   }

   @Override
   public int hashCode()
   {
      return this.resourceId;
   }

   @Override
   public String toString()
   {
      return this.name;
   }
}
