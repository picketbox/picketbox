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
package org.jboss.test.authorization.acl;

import java.util.Map;

import org.jboss.security.acl.ACLProviderImpl;
import org.jboss.security.authorization.PolicyRegistration;
import org.jboss.security.plugins.acl.PolicyRegistrationStrategy;

// $Id$

/**
 * <p>
 * This is an {@code ACLProvider} implementation used in tests that uses an instance of
 * {@code PolicyRegistrationStrategy} to look up the ACLs.
 * </p>
 * 
 * @author Anil.Saldhana@redhat.com
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @since Jan 30, 2008
 * @version $Revision$
 */
public class TestACLProvider extends ACLProviderImpl
{

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.acl.ACLProviderImpl#initialize(java.util.Map, java.util.Map)
    */
   @Override
   public void initialize(Map<String, Object> sharedState, Map<String, Object> options)
   {
      // test implementation: create an instance of PolicyRegistrationStrategy and sets the PolicyRegistration.
      PolicyRegistration registration = (PolicyRegistration) options.get("policyRegistration");
      this.setPersistenceStrategy(new PolicyRegistrationStrategy(registration));
   }
}
