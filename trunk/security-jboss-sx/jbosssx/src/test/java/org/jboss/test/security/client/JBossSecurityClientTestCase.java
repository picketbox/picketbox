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
package org.jboss.test.security.client;

import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.SecurityContextFactory;
import org.jboss.security.SubjectInfo;
import org.jboss.security.client.JBossSecurityClient;
import org.jboss.security.client.SecurityClient;
import org.jboss.security.client.SecurityClientFactory;
import org.jboss.test.AbstractJBossSXTest;
 
/**
 *  Test the JBoss Security Client
 *  @author Anil.Saldhana@redhat.com
 *  @since  Aug 16, 2007 
 *  @version $Revision$
 */
public class JBossSecurityClientTestCase extends AbstractJBossSXTest
{ 
   public JBossSecurityClientTestCase(String name)
   {
      super(name); 
   }
   
   public void testClient() throws Exception
   {
      SecurityClient client = SecurityClientFactory.getSecurityClient();
      assertEquals("JBossSecurityClient", JBossSecurityClient.class,client.getClass());
      client.setSimple("anil", "pass");
      client.login();
      SecurityContext sc = SecurityContextAssociation.getSecurityContext();
      assertNotNull("SecurityContext is not null", sc);
      SubjectInfo si = sc.getSubjectInfo();
      assertNotNull("SubjectInfo is not null", si);
      assertNotNull("Principal is not null", sc.getUtil().getUserPrincipal());
      assertEquals("Principal==anil", "anil", sc.getUtil().getUserPrincipal().getName());
      assertNotNull("Cred is not null", sc.getUtil().getCredential());
      assertEquals("Cred==pass", "pass", sc.getUtil().getCredential());
   }

   public void testClientWithExistingSecurityContext() throws Exception
   {
      SecurityContext prev = SecurityContextFactory.createSecurityContext("TEST");
      SecurityContextAssociation.setSecurityContext(prev);
      
      SecurityClient client = SecurityClientFactory.getSecurityClient();
      assertEquals("JBossSecurityClient", JBossSecurityClient.class,client.getClass());
      client.setSimple("anil", "pass");
      client.login();
      
      SecurityContext sc = SecurityContextAssociation.getSecurityContext();
      assertNotNull("SecurityContext is not null", sc);
      SubjectInfo si = sc.getSubjectInfo();
      assertNotNull("SubjectInfo is not null", si);
      assertNotNull("Principal is not null", sc.getUtil().getUserPrincipal());
      assertEquals("Principal==anil", "anil", sc.getUtil().getUserPrincipal().getName());
      assertNotNull("Cred is not null", sc.getUtil().getCredential());
      assertEquals("Cred==pass", "pass", sc.getUtil().getCredential());
      
      client.logout();
      assertEquals(prev, SecurityContextAssociation.getSecurityContext());
   }
}