/*
 * JBoss, Home of Professional Open Source
 * Copyright 2006, Red Hat Middleware LLC, and individual contributors
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
package org.jboss.test.security.helpers;

/**
 * A test class for the {EXT}... Util.loadPassword method. 
 * 
 * @author Scott.Stark@jboss.org
 * @version $Revision:$
 */
public class ExecPasswordCmd
{
   public static void main(String[] args)
   {
      String password = null;
      if (args != null && args.length == 1) {
         password = "password" + args[0];
      }
      else if (args != null && args.length == 2) {
         password = "password" + args[0] + String.valueOf(System.currentTimeMillis());
      }
      else {
         // honor the original value as default
         password = "password3";
      }

      System.out.println(password);
      System.out.flush();
      
   }
}
