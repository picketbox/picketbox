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
package org.jboss.security.plugins.identitytrust;

import org.jboss.logging.Logger;
import org.jboss.security.ErrorCodes;
import org.jboss.security.SecurityContext;
import org.jboss.security.identitytrust.IdentityTrustContext;
import org.jboss.security.identitytrust.IdentityTrustException;
import org.jboss.security.identitytrust.IdentityTrustManager;
import org.jboss.security.identitytrust.JBossIdentityTrustContext;

//$Id$

/**
 *  Identity Trust Manager default implementation
 *  @author Anil.Saldhana@redhat.com
 *  @since  Aug 2, 2007 
 *  @version $Revision$
 */
public class JBossIdentityTrustManager implements IdentityTrustManager
{ 
   protected static Logger log = Logger.getLogger(JBossIdentityTrustManager.class);
   protected boolean trace = log.isTraceEnabled();
   
   private String securityDomain = null; 
   private IdentityTrustContext identityTrustContext = null;
   
   public JBossIdentityTrustManager(String securityDomain)
   {
      this.securityDomain = securityDomain; 
   }
   
   public void setIdentityTrustContext(IdentityTrustContext itc)
   {
     if(itc == null)
        throw new IllegalArgumentException(ErrorCodes.NULL_ARGUMENT + "null Identity Trust Context");
     this.identityTrustContext = itc;
   }
   
   /**
    * @see IdentityTrustManager#isTrusted()
    */
   public TrustDecision isTrusted(SecurityContext securityContext)
   {  
      if(securityContext == null)
         throw new IllegalArgumentException(ErrorCodes.NULL_ARGUMENT + "Security Context is null");
      if(this.identityTrustContext == null)
         this.identityTrustContext = new JBossIdentityTrustContext(securityDomain, securityContext);
      TrustDecision td = TrustDecision.NotApplicable;
      if(this.identityTrustContext == null)
         throw new IllegalStateException(ErrorCodes.NULL_VALUE + "IdentityTrustContext is null");
       
      try
      {
         td = this.identityTrustContext.isTrusted();
      }
      catch (IdentityTrustException e)
      { 
         if(trace)
            log.trace("Trust Exception:",e);
      } 
      return td;
   }

   public String getSecurityDomain()
   { 
      return this.securityDomain;
   }
}