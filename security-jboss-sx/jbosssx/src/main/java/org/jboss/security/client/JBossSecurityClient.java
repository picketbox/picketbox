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
package org.jboss.security.client;

import java.security.Principal;

import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.SecurityContextFactory;
import org.jboss.security.SimplePrincipal;
 

/**
 *  Implementation of the SecurityClient contract <br/>
 *  
 *  <b> Usage:<b>
 *  <pre>
 *  SecurityClient sc = SecurityClientFactory.getSecurityClient(JBossSecurityClient.class)
 *  sc.setUserName(somestring);
 *  etc...
 *  sc.login();
 *  </pre>
 *  @author Anil.Saldhana@redhat.com
 *  @since  May 1, 2007 
 *  @version $Revision$
 */
public class JBossSecurityClient extends SecurityClient
{  
   protected LoginContext lc = null;
   
   private SecurityContext previousSecurityContext = null;
   
   @Override
   protected void peformSASLLogin()
   {
     throw new RuntimeException("Not Implemented");
   }

   @Override
   protected void performJAASLogin() throws LoginException
   { 
      lc = new LoginContext(this.loginConfigName, this.callbackHandler);
      lc.login();
   }

   @Override
   protected void performSimpleLogin()
   { 
      Principal up = null;
      if(userPrincipal instanceof String)
         up = new SimplePrincipal((String)userPrincipal);
      else 
         up = (Principal) userPrincipal;
      
      previousSecurityContext = SecurityContextAssociation.getSecurityContext();
      
      SecurityContext sc = null; 
      try
      {
         sc = SecurityContextFactory.createSecurityContext("CLIENT");
      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      }
      sc.getUtil().createSubjectInfo(up, credential, null);
      SecurityContextAssociation.setSecurityContext(sc);
   }

   @Override
   protected void cleanUp()
   {
      SecurityContextAssociation.setSecurityContext(previousSecurityContext); 
      if(lc != null)
         try
         {
            lc.logout();
         }
         catch (LoginException e)
         {
            throw new RuntimeException(e);
         }
   } 
}