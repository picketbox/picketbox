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
package org.jboss.security.auth.spi;

import org.jboss.logging.Logger;
import org.jboss.xb.binding.ObjectModelFactory;
import org.jboss.xb.binding.UnmarshallingContext;
import org.xml.sax.Attributes;

/** A JBossXB object factory for parsing the 
 * @author Scott.Stark@jboss.org
 * @version $Revision$
 */
public class UsersObjectModelFactory implements ObjectModelFactory
{
   private static Logger log = Logger.getLogger(UsersObjectModelFactory.class);
   private boolean trace = log.isTraceEnabled();
   
   public Object newRoot(Object root, UnmarshallingContext navigator,
      String namespaceURI, String localName, Attributes attrs)
   {
      if (!localName.equals("users"))
      {
         throw new IllegalStateException("Unexpected root element: was expecting 'users' but got '" + localName + "'");
      }
      if(trace)
         log.trace("newRoot, root="+root);
      return new Users();
   }

   public Object completeRoot(Object root, UnmarshallingContext ctx, String uri, String name)
   {
      return root;
   }
   
   public void setValue(Users users, UnmarshallingContext navigator,
      String namespaceUri, String localName, String value)
   {
   }

   public Object newChild(Users users, UnmarshallingContext navigator,
      String namespaceUri, String localName, Attributes attrs)
   {
      Users.User child = null;
      if("user".equals(localName))
      {
         String name = attrs.getValue("name");
         child = new Users.User(name);
         String password = attrs.getValue("password");
         child.setPassword(password);
         String encoding = attrs.getValue("encoding");
         child.setEncoding(encoding);
         if(trace)
            log.trace("newChild, user="+child);
      }
      return child;
   }

   public void addChild(Users users, Users.User user,
      UnmarshallingContext navigator, String namespaceURI, String localName)
   {
      users.addUser(user);
   }

   public Object newChild(Users.User user, UnmarshallingContext navigator,
      String namespaceUri, String localName, Attributes attrs)
   {
      String[] roleInfo = {null, "Roles"};
      if("role".equals(localName))
      {
         roleInfo[0] = attrs.getValue("name");
         roleInfo[1] = attrs.getValue("group");
         if( roleInfo[1] == null )
            roleInfo[1] = "Roles";
      }
      return roleInfo;
   }

   public void addChild(Users.User user, String[] roleInfo,
      UnmarshallingContext navigator, String namespaceURI, String localName)
   {
      user.addRole(roleInfo[0], roleInfo[1]);
   }
}