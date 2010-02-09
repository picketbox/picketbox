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
package org.jboss.test.securitycontext;

import java.util.Map;

import org.jboss.security.AuthenticationManager;
import org.jboss.security.AuthorizationManager;
import org.jboss.security.ISecurityManagement;
import org.jboss.security.RunAs;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextUtil;
import org.jboss.security.SubjectInfo;
import org.jboss.security.audit.AuditManager;
import org.jboss.security.identitytrust.IdentityTrustManager;
import org.jboss.security.mapping.MappingManager;

//$Id$

/**
 *  Test Security Context
 *  @author Anil.Saldhana@redhat.com
 *  @since  Sep 8, 2007 
 *  @version $Revision$
 */
public class TestSecurityContext implements SecurityContext
{ 
   private static final long serialVersionUID = 1L;

   public TestSecurityContext(String secDomain)
   {   
   } 
   
   public Map<String, Object> getData()
   {
      return null;
   }
 
   public RunAs getIncomingRunAs()
   {
      return null;
   }
 
   public RunAs getOutgoingRunAs()
   {
      return null;
   }

   public String getSecurityDomain()
   {
      return null;
   }

   public void setSecurityDomain(String domain)
   {
   }
   
   public SubjectInfo getSubjectInfo()
   {
      return null;
   }

   public SecurityContextUtil getUtil()
   {
      return null;
   }

   public void setIncomingRunAs(RunAs arg0)
   {
   }
   public void setOutgoingRunAs(RunAs arg0)
   {
   }

   public void setSubjectInfo(SubjectInfo arg0)
   {
   }

   public ISecurityManagement getSecurityManagement()
   {
      return null;
   }

   public void setSecurityManagement(ISecurityManagement arg0)
   {
   }

   public AuditManager getAuditManager()
   {
      return null;
   }

   public AuthenticationManager getAuthenticationManager()
   {
      return null;
   }

   public AuthorizationManager getAuthorizationManager()
   {
      return null;
   }

   public IdentityTrustManager getIdentityTrustManager()
   { 
      return null;
   }

   public MappingManager getMappingManager()
   {
      return null;
   } 
}