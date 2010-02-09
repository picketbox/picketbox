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
package org.jboss.test.security.microcontainer.metadata;

import junit.framework.Test;
import junit.framework.TestSuite;

/**
 * <p>
 * This class implements a {@code TestSuite} for the application policy tests.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class ApplicationPolicyTestSuite extends TestSuite
{
   /**
    * <p>
    * Creates and returns a {@code TestSuite} containing all application policy tests.
    * </p>
    * 
    * @return a reference to the constructed {@code TestSuite}.
    */
   public static Test suite()
   {
      TestSuite suite = new TestSuite("Application policy tests");
      suite.addTestSuite(BasicApplicationPolicyTestCase.class);
      suite.addTestSuite(AuthorizationPolicyTestCase.class);
      suite.addTestSuite(ACLPolicyTestCase.class);
      suite.addTestSuite(RoleMappingPolicyTestCase.class);
      suite.addTestSuite(MappingPolicyTestCase.class);
      suite.addTestSuite(AuditPolicyTestCase.class);
      suite.addTestSuite(IdentityTrustPolicyTestCase.class);
      suite.addTestSuite(ApplicationPolicyMixedTestCase.class);
      suite.addTestSuite(ApplicationPolicyExtendsTestCase.class);
      suite.addTestSuite(InvalidApplicationPolicyTestCase.class);
      suite.addTestSuite(ManagersInjectionTestCase.class);

      return suite;
   }
}
