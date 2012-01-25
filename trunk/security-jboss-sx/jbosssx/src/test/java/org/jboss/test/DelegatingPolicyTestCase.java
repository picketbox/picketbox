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

import java.lang.reflect.Constructor;
import java.security.AccessControlContext;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.CodeSource;
import java.security.Policy;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.ProtectionDomain;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.jacc.EJBMethodPermission;
import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyConfigurationFactory;
import javax.security.jacc.PolicyContext;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.apache.log4j.Logger;
import org.jboss.security.SecurityConstants;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.jacc.DelegatingPolicy;
import org.jboss.security.jacc.SubjectPolicyContextHandler;

public class DelegatingPolicyTestCase extends TestCase
{
   private static Logger log = Logger.getLogger(DelegatingPolicyTestCase.class);
   private static Policy oldPolicy;
   private static Policy jaccPolicy;

   public DelegatingPolicyTestCase(String name)
   {
      super(name);
   }

   static void setUpPolicy() throws Exception
   {
      // Get the current Policy impl
      oldPolicy = Policy.getPolicy();

      String provider = "org.jboss.security.jacc.DelegatingPolicy";
      ClassLoader loader = Thread.currentThread().getContextClassLoader();
      Class<?> providerClass = loader.loadClass(provider);
      try
      {
         // Look for a ctor(Policy) signature
         Class<?>[] ctorSig = {Policy.class};
         Constructor<?> ctor = providerClass.getConstructor(ctorSig);
         Object[] ctorArgs = {oldPolicy};
         jaccPolicy = (Policy) ctor.newInstance(ctorArgs);
      }
      catch(NoSuchMethodException e)
      {
         log.debug("Provider does not support ctor(Policy)");
         jaccPolicy = (Policy) providerClass.newInstance();
      }

      // Install the JACC policy provider
      Policy.setPolicy(jaccPolicy);

      // Have the policy load/update itself
      jaccPolicy.refresh();

      // Register the default active Subject PolicyContextHandler
      SubjectPolicyContextHandler handler = new SubjectPolicyContextHandler();
      PolicyContext.registerHandler(SecurityConstants.SUBJECT_CONTEXT_KEY,
         handler, false);
   }

   /**
    * Basic test that a PolicyConfiguration is included in the Policy and its
    * permissions are implied through the Policy.
    * 
    * @throws Exception
    */ 
   public void testPolicyConfiguration() throws Exception
   {
      PolicyConfigurationFactory pcf = PolicyConfigurationFactory.getPolicyConfigurationFactory();
      PolicyConfiguration pc = pcf.getPolicyConfiguration("context-a", false);
      EJBMethodPermission someEJB = new EJBMethodPermission("someEJB", null);
      pc.addToExcludedPolicy(someEJB);
      pc.commit();

      Policy sysPolicy = Policy.getPolicy();
      assertTrue("Policy isa DelegatingPolicy", sysPolicy instanceof DelegatingPolicy);
      sysPolicy.refresh();

      // Act like the ejb container and check a permission
      PolicyContext.setContextID("context-a");
      EJBMethodPermission methodX = new EJBMethodPermission("someEJB", "methodX,,int");
      assertTrue("methodX denied", sysPolicy.implies(null, methodX) == false);

      pc = pcf.getPolicyConfiguration("context-a", true);
      pc.addToUncheckedPolicy(someEJB);
      pc.commit();
      sysPolicy.refresh();
      assertTrue("methodX allowed", sysPolicy.implies(null, methodX) == true);

      pc.delete();
      pc = pcf.getPolicyConfiguration("context-a", false);
      pc.addToRole("callerX", someEJB);
      pc.commit();
      sysPolicy.refresh();
      SimplePrincipal[] callers = {new SimplePrincipal("callerX")};
      ProtectionDomain pd = new ProtectionDomain(null, null, null, callers);
      assertTrue("methodX allowed", sysPolicy.implies(pd, methodX) == true);

      callers = new SimplePrincipal[]{new SimplePrincipal("callerY")};
      pd = new ProtectionDomain(null, null, null, callers);
      assertTrue("methodX denied", sysPolicy.implies(pd, methodX) == false);

   }

   /**
    * Test that uncommitted configurations in the Open state are not seen in
    * the current Policy permission set.
    * 
    * @throws Exception
    */ 
   public void testOpenConfigurations() throws Exception
   {
      PolicyConfigurationFactory pcf = PolicyConfigurationFactory.getPolicyConfigurationFactory();
      PolicyConfiguration pc = pcf.getPolicyConfiguration("context-a", false);
      EJBMethodPermission someEJB = new EJBMethodPermission("someEJB", null);
      pc.addToRole("callerX", someEJB);
      Policy sysPolicy = Policy.getPolicy();

      pc = pcf.getPolicyConfiguration("context-a", true);
      pc.addToUncheckedPolicy(someEJB);
      sysPolicy.refresh();
      EJBMethodPermission methodX = new EJBMethodPermission("someEJB", "methodX,,int");
      // This perm should be denied since the policy config has not been comitted
      boolean implied = sysPolicy.implies(null, methodX);
      assertFalse("methodX allowed",implied == true);

      pc.commit();
      sysPolicy.refresh();
      // Now it should be allowed since the policy config has been comitted
      implied = sysPolicy.implies(null, methodX);
      assertTrue("methodX allowed", implied  == true);
   }

   public void testSubjectDoAs() throws Exception
   {
      PolicyConfigurationFactory pcf = PolicyConfigurationFactory.getPolicyConfigurationFactory();
      PolicyConfiguration pc = pcf.getPolicyConfiguration("context-a", true);
      EJBMethodPermission someEJB = new EJBMethodPermission("someEJB", null);
      pc.addToRole("callerX", someEJB);
      pc.commit();

      log.debug("EJBMethodPermission.CS: "+EJBMethodPermission.class.getProtectionDomain());
      final EJBMethodPermission methodX = new EJBMethodPermission("someEJB", "methodX");
      final Subject caller = new Subject();
      caller.getPrincipals().add(new SimplePrincipal("callerX"));
      Set<Principal> principalsSet = caller.getPrincipals();
      Principal[] principals = new Principal[principalsSet.size()];
      principalsSet.toArray(principals);
      CodeSource cs = getClass().getProtectionDomain().getCodeSource();
      final ProtectionDomain[] pds = {new ProtectionDomain (cs, null, null, principals)};
      AccessControlContext acc = new AccessControlContext(pds);
      /*
      AccessControlContext acc = new AccessControlContext(new AccessControlContext(pds),
               new SubjectDomainCombiner(caller));
      */

      Boolean allowed = (Boolean) Subject.doAsPrivileged(caller, new PrivilegedAction<Boolean>()
         {
            public Boolean run()
            {
               AccessControlContext acc = AccessController.getContext();
               Boolean ok = Boolean.FALSE;
               try
               {
                  acc.checkPermission(methodX);
                  ok = Boolean.TRUE;
               }
               catch(AccessControlException e)
               {
                  
               }
               return ok;
            }
         }, acc
      );
      assertTrue("methodX allowed", allowed == Boolean.TRUE );
      
   }

   public static Test suite()
   {
      TestSuite suite = new TestSuite(DelegatingPolicyTestCase.class);

      // Create an initializer for the test suite
      TestSetup wrapper = new TestSetup(suite)
      {
         protected void setUp() throws Exception
         {
            setUpPolicy();
         }
         protected void tearDown() throws Exception
         {
         }
      };
      return wrapper;
   }
}
