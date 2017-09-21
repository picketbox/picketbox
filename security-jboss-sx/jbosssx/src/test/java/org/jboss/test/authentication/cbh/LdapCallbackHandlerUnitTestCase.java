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
package org.jboss.test.authentication.cbh;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.naming.AuthenticationException;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;

import org.jboss.security.auth.callback.LdapCallbackHandler;
import org.jboss.security.auth.callback.VerifyPasswordCallback;
import org.jboss.test.security.ldap.OpenDSUnitTestsAdapter;
import org.junit.Test;

/**
 * Unit test the {@code LdapCallbackHandler}
 * @author Anil Saldhana
 * @since Oct 31, 2011
 */
public class LdapCallbackHandlerUnitTestCase extends OpenDSUnitTestsAdapter
{
	public LdapCallbackHandlerUnitTestCase(String name) 
	{
		super(name);
	}
	
	protected void setUp() throws Exception
	{
		super.setUp();

		//Let us add the ldapAttributes.ldif
		String fileName = targetDir + "ldap" + fs + "ldapAttributes.ldif";
		boolean op = util.addLDIF(serverHost, port, adminDN, adminPW, new File(fileName).toURI().toURL());
		assertTrue(op);
	}

	@Override
	public void tearDown() throws Exception {
		super.tearDown();
	}

	@Test
	public void testSuccessfulCBH() throws Exception
	{
		LdapCallbackHandler cbh = new LdapCallbackHandler();
		
		Map<String,String> map = new HashMap<String,String>();
		map.put("bindDN", "cn=Directory Manager");
		map.put("bindCredential", "password");
		map.put("baseFilter", "(uid={0})");
		map.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");
		map.put("java.naming.provider.url", "ldap://localhost:10389");
	    map.put("baseCtxDN", "ou=People,dc=jboss,dc=org");
        
        cbh.setConfiguration(map);
        
		NameCallback ncb = new NameCallback("Enter");
		ncb.setName("jduke");
		
		VerifyPasswordCallback vpc = new VerifyPasswordCallback();
		vpc.setValue("theduke");
		 
		cbh.handle(new Callback[] {ncb,vpc} );
		
		assertTrue(vpc.isVerified());
	}
	
	@Test
	public void testFailCBH() throws Exception
	{
		LdapCallbackHandler cbh = new LdapCallbackHandler();
		
		Map<String,String> map = new HashMap<String,String>();
		map.put("bindDN", "cn=Directory Manager");
		map.put("bindCredential", "password");
		map.put("baseFilter", "(uid={0})");
		map.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");
		map.put("java.naming.provider.url", "ldap://localhost:10389");
	    map.put("baseCtxDN", "ou=People,dc=jboss,dc=org");
        
        cbh.setConfiguration(map);
        
		NameCallback ncb = new NameCallback("Enter");
		ncb.setName("jduke");
		
		VerifyPasswordCallback vpc = new VerifyPasswordCallback();
		vpc.setValue("badDUDE");
		 
		try
		{
			cbh.handle(new Callback[] {ncb,vpc} );
			fail("should have thrown ex");
		}
		catch(IOException ae)
		{
			Throwable cause = ae.getCause();
			assertNotNull(cause);
			assertTrue(cause instanceof AuthenticationException);
		}
		
		assertFalse(vpc.isVerified());
	}
}