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
package org.jboss.security;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.MessageInfo;

/**
 * AuthenticationManager with JSR-196 Semantics
 * @author Anil.Saldhana@redhat.com
 * @since May 30, 2008
 */
public interface ServerAuthenticationManager extends AuthenticationManager
{  
   /**
    * Authenticate a Subject given the request response JSR-196(JASPI) messages
    * @param requestMessage 
    * @param clientSubject Pre-created or null subject
    * @param layer Message Layer for the JASPI (Optional):  Default: HTTP
    * @param callbackHandler CallbackHandler
    * @return true if client subject is valid, false otherwise
    */
   boolean isValid(MessageInfo requestMessage, Subject clientSubject, String layer,
         CallbackHandler callbackHandler);
}