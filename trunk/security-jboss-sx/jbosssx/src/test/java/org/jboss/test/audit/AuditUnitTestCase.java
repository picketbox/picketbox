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
package org.jboss.test.audit; 

import junit.framework.TestCase;

import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextFactory;
import org.jboss.security.audit.AuditEvent;
import org.jboss.security.audit.AuditLevel;
import org.jboss.security.audit.AuditManager;
import org.jboss.security.audit.config.AuditProviderEntry;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.AuditInfo;
import org.jboss.security.config.SecurityConfiguration;

//$Id$

/**
 *  Tests for the Auditing Layer
 *  @author Anil.Saldhana@redhat.com
 *  @since  May 10, 2007 
 *  @version $Revision$
 */
public class AuditUnitTestCase extends TestCase
{ 
   @Override
   protected void setUp() throws Exception
   {
      super.setUp();
      setUpSecurityConfiguration();
   }
   
   /**
    * We invoke the AuditManager on the security context to audit
    * a particular AuditEvent. The AuditManager is configured with a 
    * test logging provider that basically places the event on a 
    * thread local of a static class. The test then checks the 
    * thread local for the audit event.
    */
   public void testAuditConfiguration() throws Exception
   {
      SecurityContext sc = SecurityContextFactory.createSecurityContext("test");
      AuditManager am = sc.getAuditManager();
      AuditEvent ae = new AuditEvent(AuditLevel.ERROR);
      am.audit(ae);
      
      //Now check that the Audit Event has been placed on the thread local
      //by our TestAuditProvider
      AuditEvent aev = (AuditEvent) AuditTestAssociation.auditEventLocal.get();
      assertEquals("Audit events are the same", ae, aev);
   }
   
   
   private void setUpSecurityConfiguration()
   {
      String p = TestAuditProvider.class.getName();
      
      ApplicationPolicy ap = new ApplicationPolicy("test");
      AuditInfo auditInfo = new AuditInfo("test");
      AuditProviderEntry ape = new AuditProviderEntry(p);
      auditInfo.add(ape); 
      ap.setAuditInfo(auditInfo);
      SecurityConfiguration.addApplicationPolicy(ap);
   } 
}
