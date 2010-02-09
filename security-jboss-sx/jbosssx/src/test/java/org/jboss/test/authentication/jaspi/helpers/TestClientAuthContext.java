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
package org.jboss.test.authentication.jaspi.helpers;

import javax.security.auth.Subject;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.ClientAuthContext;

//$Id$

/**
 *  Test ClientAuthContext
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 16, 2007 
 *  @version $Revision$
 */
public class TestClientAuthContext implements ClientAuthContext
{ 
   public void cleanSubject(MessageInfo messageInfo, Subject arg1) 
   throws AuthException
   { 
   }

   public AuthStatus secureRequest(MessageInfo messageInfo, Subject arg1) 
   throws AuthException
   { 
      return null;
   }

   public AuthStatus validateResponse(MessageInfo messageInfo, 
         Subject arg1, Subject arg2) 
   throws AuthException
   { 
      return null;
   } 
}
