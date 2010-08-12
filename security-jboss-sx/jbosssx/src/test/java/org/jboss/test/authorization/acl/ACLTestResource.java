/*
  * JBoss, Home of Professional Open Source
  * Copyright 2007, JBoss Inc., and individual contributors as indicated
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
package org.jboss.test.authorization.acl;

import java.util.HashMap;
import java.util.Map;

import org.jboss.security.authorization.Resource;
import org.jboss.security.authorization.ResourceType;

//$Id$

/**
 *  Test Resource For ACL
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jan 30, 2008 
 *  @version $Revision$
 */
public class ACLTestResource implements Resource
{

   private final int id;

   private final Map<String, Object> contextMap = new HashMap<String, Object>();
   
   /**
    * <p>
    * Creates an instance of {@code ACLTestResource} with the specified id.
    * </p>
    * 
    * @param id an {@code int} representing the resource's id.
    */
   public ACLTestResource(int id)
   {
      this.id = id;
   }
   
   /*
    * (non-Javadoc)
    * @see org.jboss.security.authorization.Resource#getLayer()
    */
   public ResourceType getLayer()
   {
      return ResourceType.ACL;
   }

   /*
    * (non-Javadoc)
    * @see org.jboss.security.authorization.Resource#getMap()
    */
   public Map<String, Object> getMap()
   {
      return this.contextMap;
   }
   
   /**
    * <p>
    * Obtains the id of this test resource.
    * </p>
    * 
    * @return an {@code int} representing this resource's id.
    */
   public int getId()
   {
      return this.id;
   }

   public void add(String key, Object value)
   {
      this.contextMap.put(key, value);
   }
}
