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
package org.jboss.test.security.identitytrust;

import java.net.URL;

import junit.framework.TestCase;

import org.jboss.security.RunAs;
import org.jboss.security.RunAsIdentity;
import org.jboss.security.auth.login.XMLLoginConfigImpl;
import org.jboss.security.identitytrust.IdentityTrustManager;
import org.jboss.security.identitytrust.IdentityTrustManager.TrustDecision;
import org.jboss.security.plugins.JBossSecurityContext;
import org.jboss.test.SecurityActions;

// $Id$

/**
 * Test the IdentityTrust framework
 * 
 * @author Anil.Saldhana@redhat.com
 * @since Aug 2, 2007
 * @version $Revision$
 */
public class IdentityTrustUnitTestCase extends TestCase
{
   String configFile = "config/identitytrust-config.xml";

   @Override
   protected void setUp() throws Exception
   {
      XMLLoginConfigImpl xli = XMLLoginConfigImpl.getInstance();
      SecurityActions.setJAASConfiguration(xli);
      URL configURL = Thread.currentThread().getContextClassLoader().getResource(configFile);
      assertNotNull("Config URL", configURL);

      xli.setConfigURL(configURL);
      xli.loadConfig();
   }

   public void testPermit_Permit_Permit() throws Exception
   {
      JBossSecurityContext sc = new JBossSecurityContext("Permit-Permit-Permit");
      sc.setIncomingRunAs(new RunAsIdentity("theduke", "jduke"));
      assertNotNull("SecurityContext is not null", sc);
      IdentityTrustManager itm = sc.getIdentityTrustManager();
      assertNotNull("IdentityTrustManager is not null", itm);
      assertEquals("Is Trusted", TrustDecision.Permit, itm.isTrusted(sc));
   }

   public void testPermit_Permit_Deny() throws Exception
   {
      JBossSecurityContext sc = new JBossSecurityContext("Permit-Permit-Deny");
      sc.setIncomingRunAs(new RunAsIdentity("theduke", "jduke"));
      assertNotNull("SecurityContext is not null", sc);
      IdentityTrustManager itm = sc.getIdentityTrustManager();
      assertNotNull("IdentityTrustManager is not null", itm);
      assertEquals("Is Trusted Deny", TrustDecision.Deny, itm.isTrusted(sc));
   }

   public void testPermit_Deny_Permit() throws Exception
   {
      JBossSecurityContext sc = new JBossSecurityContext("Permit-Deny-Permit");
      sc.setIncomingRunAs(new RunAsIdentity("theduke", "jduke"));
      assertNotNull("SecurityContext is not null", sc);
      IdentityTrustManager itm = sc.getIdentityTrustManager();
      assertNotNull("IdentityTrustManager is not null", itm);
      assertEquals("Is Trusted Deny", TrustDecision.Deny, itm.isTrusted(sc));
   }

   public void testDeny_Permit_Permit() throws Exception
   {
      JBossSecurityContext sc = new JBossSecurityContext("Deny-Permit-Permit");
      sc.setIncomingRunAs(new RunAsIdentity("theduke", "jduke"));
      assertNotNull("SecurityContext is not null", sc);
      IdentityTrustManager itm = sc.getIdentityTrustManager();
      assertNotNull("IdentityTrustManager is not null", itm);
      assertEquals("Is Trusted Deny", TrustDecision.Deny, itm.isTrusted(sc));
   }

   public void testPermit_Permit_NotApplicable() throws Exception
   {
      JBossSecurityContext sc = new JBossSecurityContext("Permit-Permit-NotApplicable");
      sc.setIncomingRunAs(new RunAsIdentity("theduke", "jduke"));
      assertNotNull("SecurityContext is not null", sc);
      IdentityTrustManager itm = sc.getIdentityTrustManager();
      assertNotNull("IdentityTrustManager is not null", itm);
      assertEquals("Is Trusted", TrustDecision.Permit, itm.isTrusted(sc));
   }

   public void testNotApplicable_Permit_Permit() throws Exception
   {
      JBossSecurityContext sc = new JBossSecurityContext("NotApplicable-Permit-Permit");
      sc.setIncomingRunAs(new RunAsIdentity("theduke", "jduke"));
      assertNotNull("SecurityContext is not null", sc);
      IdentityTrustManager itm = sc.getIdentityTrustManager();
      assertNotNull("IdentityTrustManager is not null", itm);
      assertEquals("Is Trusted", TrustDecision.Permit, itm.isTrusted(sc));
   }

   public void testNotApplicable_Required__Permit_Optional() throws Exception
   {
      JBossSecurityContext sc = new JBossSecurityContext("NotApplicable_Required-Permit_Optional");
      sc.setIncomingRunAs(new RunAsIdentity("theduke", "jduke"));
      assertNotNull("SecurityContext is not null", sc);
      IdentityTrustManager itm = sc.getIdentityTrustManager();
      assertNotNull("IdentityTrustManager is not null", itm);
      assertEquals("Is Trusted not applicable", TrustDecision.NotApplicable, itm.isTrusted(sc));
   }

   public void testPermit_Required__Deny_Optional() throws Exception
   {
      JBossSecurityContext sc = new JBossSecurityContext("Permit_Required-Deny_Optional");
      sc.setIncomingRunAs(new RunAsIdentity("theduke", "jduke"));
      assertNotNull("SecurityContext is not null", sc);
      IdentityTrustManager itm = sc.getIdentityTrustManager();
      assertNotNull("IdentityTrustManager is not null", itm);
      assertEquals("Is Trusted", TrustDecision.Permit, itm.isTrusted(sc));
   }

   public void testNotApplicable_Required__Deny_Optional() throws Exception
   {
      JBossSecurityContext sc = new JBossSecurityContext("NotApplicable_Required-Deny_Optional");
      sc.setIncomingRunAs(new RunAsIdentity("theduke", "jduke"));
      assertNotNull("SecurityContext is not null", sc);
      IdentityTrustManager itm = sc.getIdentityTrustManager();
      assertNotNull("IdentityTrustManager is not null", itm);
      assertEquals("Is Trusted false", TrustDecision.NotApplicable, itm.isTrusted(sc));
   }

   public void testPermit_Sufficient__Deny_Optional() throws Exception
   {
      JBossSecurityContext sc = new JBossSecurityContext("Permit_Sufficient-Deny_Optional");
      sc.setIncomingRunAs(new RunAsIdentity("theduke", "jduke"));
      assertNotNull("SecurityContext is not null", sc);
      IdentityTrustManager itm = sc.getIdentityTrustManager();
      assertNotNull("IdentityTrustManager is not null", itm);
      assertEquals("Is Trusted", TrustDecision.Permit, itm.isTrusted(sc));
   }

   @SuppressWarnings("unchecked")
   public void testJavaEERunAsIdentity() throws Exception
   {
      JBossSecurityContext sc = new JBossSecurityContext("conf-javaee");
      sc.setIncomingRunAs(new RunAsIdentity("theduke", "jduke"));
      assertNotNull("SecurityContext is not null", sc);
      IdentityTrustManager itm = sc.getIdentityTrustManager();
      assertNotNull("IdentityTrustManager is not null", itm);
      assertEquals("Is Trusted", TrustDecision.Permit, itm.isTrusted(sc));

      sc.setIncomingRunAs(new RunAs()
      {
         public <T> T getIdentity()
         {
            return (T) "BAD";
         }

         public <T> T getProof()
         {
            return (T) "BAD";
         }

         public String getName()
         {
            return "BAD";
         }
      });

      assertEquals("Is Trusted is false", TrustDecision.NotApplicable, itm.isTrusted(sc));
   }
}
