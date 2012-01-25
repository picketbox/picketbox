/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2010, Red Hat Middleware LLC, and individual contributors
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
package org.jboss.security.plugins;

import java.security.Principal;

import javax.security.auth.Subject;

import org.jboss.logging.Logger;
import org.jboss.security.AuthenticationManager;
import org.jboss.security.ErrorCodes;
import org.jboss.security.ISecurityManagement;
import org.jboss.security.SecurityConstants;
import org.jboss.security.SubjectFactory;
import org.jboss.security.auth.callback.JBossCallbackHandler;

/**
 * Create a Subject given the details available
 * via implementation strategies such as SecurityContextAssociation
 * to get hold of the Principal, Credentials, etc
 * 
 * @author Anil.Saldhana@redhat.com
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @version $Revision: 1 $
 */
public class JBossSecuritySubjectFactory implements SubjectFactory
{

   private static Logger log = Logger.getLogger(JBossSecuritySubjectFactory.class);

   private ISecurityManagement securityManagement;

   /**
    * @see SubjectFactory#createSubject()
    */
   public Subject createSubject()
   {
      return createSubject(SecurityConstants.DEFAULT_APPLICATION_POLICY);
   }

   /**
    * @see SubjectFactory#createSubject(String)
    */
   public Subject createSubject(String securityDomainName)
   {
      if (securityManagement == null)
      {
         log.warn("SecurityManagement is not set. Creating a default one");
         securityManagement = new DefaultSecurityManagement(new JBossCallbackHandler());
      }
      Subject subject = new Subject();
      //Validate the caller
      Principal principal = SubjectActions.getPrincipal();
      AuthenticationManager authenticationManager = securityManagement.getAuthenticationManager(securityDomainName);
      if (authenticationManager == null)
      {
         String defaultSecurityDomain = SecurityConstants.DEFAULT_APPLICATION_POLICY;
         if (log.isTraceEnabled())
         {
            log.trace("AuthenticationManager for " + securityDomainName + " not found. Using " + defaultSecurityDomain);
         }
         authenticationManager = securityManagement.getAuthenticationManager(defaultSecurityDomain);
      }
      //AS7-1072: we can't have TCCL null or else LoginContext can't find the login modules
      ClassLoader tccl = SubjectActions.getContextClassLoader();
      try
      {
         SubjectActions.setContextClassLoader(this.getClass().getClassLoader());
         if (!authenticationManager.isValid(principal, SubjectActions.getCredential(), subject))
            throw new SecurityException(ErrorCodes.ACCESS_DENIED + "Unauthenticated caller:" + principal);
      }
      finally
      {
         SubjectActions.setContextClassLoader(tccl);
      }
      return subject;
   }

   /**
    * Sets the {@link ISecurityManagement} implementation to be used.
    * If this is not set, a default implementation will be used. 
    * 
    * @param securityManagement the concrete implementation to be used
    */
   public void setSecurityManagement(ISecurityManagement securityManagement)
   {
      this.securityManagement = securityManagement;
   }

}
