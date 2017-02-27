/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016, Red Hat Middleware LLC, and individual contributors
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

package org.jboss.test.auth.spi;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.acl.Group;

import org.jboss.security.auth.spi.UsernamePasswordLoginModule;
import org.junit.Before;
import org.junit.Test;

public class UsernamePasswordLoginModuleTestCase {

    private TestLoginModule loginModule;

    @Before
    public void setUp()
    {
        this.loginModule = new TestLoginModule();
    }

    @Test
    public void testEqualPasswords()
    {
        assertTrue(this.loginModule.validatePassword("aaa", "aaa"));
        assertTrue(this.loginModule.validatePassword("aaa", new String("aaa")));
        assertTrue(this.loginModule.validatePassword("aaa" + Character.MAX_SURROGATE, "aaa" + Character.MAX_SURROGATE));
        assertTrue(this.loginModule.validatePassword("aaa" + Character.MAX_SURROGATE, new String("aaa" + Character.MAX_SURROGATE)));
    }

    @Test
    public void testNotEqualPasswords()
    {
        assertFalse(this.loginModule.validatePassword(null, null));

        assertFalse(this.loginModule.validatePassword("aaa", "aaaa"));
        assertFalse(this.loginModule.validatePassword("aaa", "aab"));
        assertFalse(this.loginModule.validatePassword("aaa", "baa"));
        assertFalse(this.loginModule.validatePassword("aaa", "AAA"));

        assertFalse(this.loginModule.validatePassword("aaa" + Character.MAX_SURROGATE, "aaa"));
        assertFalse(this.loginModule.validatePassword("aa" + Character.MAX_SURROGATE, "aaa"));
        assertFalse(this.loginModule.validatePassword(Character.MAX_SURROGATE + "aa", "aaa"));
        assertFalse(this.loginModule.validatePassword("aaa", null));
        assertFalse(this.loginModule.validatePassword(null, "aaa"));
    }

    public static class TestLoginModule extends UsernamePasswordLoginModule
    {
        @Override
        public boolean validatePassword(String inputPassword, String expectedPassword)
        {
            return super.validatePassword(inputPassword, expectedPassword);
        }

        @Override
        protected Group[] getRoleSets()
        {
            return new Group[0];
        }


       /** This represents the 'true' password
        */
       @Override
       protected String getUsersPassword()
       {
          return "verySecret";
       }
    }

}
