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
package org.jboss.test;

import org.jboss.security.auth.spi.Util;


/** A utility program for generating password hashes given the hashAlgorithm,
hashEncoding, and hashCharset options used by the UsernamePasswordLoginModule.
The command line usage is:
PasswordHasher [hashAlgorithm [hashEncoding [hashCharset]]] password

 @author Scott.Stark@jboss.org
 @version $Revision$
 */
public class PasswordHasher
{
   static String usage = "Usage: [hashAlgorithm [hashEncoding [hashCharset]]] password";

   /** @param args the command line arguments
    *Usage: [hashAlgorithm [hashEncoding [hashCharset]]] password
    */
   public static void main(String[] args)
   {
      String hashAlgorithm = "MD5";
      String hashEncoding = "base64";
      String hashCharset = null;
      String password = null;
      if( args.length == 0 || args[0].startsWith("-h") )
         throw new IllegalStateException(usage);
      switch( args.length )
      {
         case 4:
            hashAlgorithm = args[0];
            hashEncoding = args[1];
            hashCharset = args[2];
            password = args[3];
         break;
         case 3:
            hashAlgorithm = args[0];
            hashEncoding = args[1];
            password = args[2];
         break;
         case 2:
            hashAlgorithm = args[0];
            password = args[1];
         break;
         case 1:
            password = args[0];
         break;
      }
      String passwordHash = Util.createPasswordHash(hashAlgorithm, hashEncoding,
         hashCharset, null, password);
      System.out.println("passwordHash = "+passwordHash);
   }

}
