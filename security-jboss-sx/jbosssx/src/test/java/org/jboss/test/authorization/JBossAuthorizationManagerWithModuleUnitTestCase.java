/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat Middleware LLC, and individual contributors
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
package org.jboss.test.authorization;

import java.util.Set;

import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.AuthorizationInfo;
import org.jboss.security.config.SecurityConfiguration;
import org.jboss.security.plugins.ClassLoaderLocator;
import org.jboss.security.plugins.ClassLoaderLocatorFactory;

/**
 * Use of module attribute
 * @author Anil Saldhana
 * @since Nov 16, 2011
 */
public class JBossAuthorizationManagerWithModuleUnitTestCase extends
		JBossAuthorizationManagerUnitTestCase 
{
	@Override
	protected void setSecurityConfiguration() throws Exception 
	{
		super.setSecurityConfiguration();
		ApplicationPolicy ap = SecurityConfiguration.getApplicationPolicy("other");
		AuthorizationInfo ai = ap.getAuthorizationInfo();
		ai.addJBossModuleName("org.picketbox");
		ap.setAuthorizationInfo(ai);
		SecurityConfiguration.addApplicationPolicy(ap);
		
		ClassLoaderLocatorFactory.set(new ClassLoaderLocator() {
			
			public ClassLoader get(Set<String> modules) {
				return Thread.currentThread().getContextClassLoader();
			}
		});
	}
}