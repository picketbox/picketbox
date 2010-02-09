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

import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.jboss.security.SimplePrincipal;

/** Tests of propagating the security identity across threads using
InheritableThreadLocal.

@author Scott.Stark@jboss.org
@version $Revision$
*/
public class ThreadLocalTestCase extends TestCase
{
    private static InheritableThreadLocal thread_principal = new InheritableThreadLocal();
    private static InheritableThreadLocal thread_credential = new InheritableThreadLocal();
    private static String USER = "jduke";
    private static String PASSWORD = "theduke";

    public ThreadLocalTestCase(String name)
    {
        super(name);
    }

    public void testSecurityPropagation() throws Exception
    {
        // Assign the principal & crendentials for this thread
        SimplePrincipal user = new SimplePrincipal(USER);
        thread_principal.set(user);
        thread_credential.set(PASSWORD);
        // Spawn a thread 
        Thread t = new Thread(new Child(), "testSecurityPropagation");
        t.start();
        t.join();
    }

    public void testSecurityPropagation2() throws Exception
    {
        // Assign the principal & crendentials for this thread
        SimplePrincipal user = new SimplePrincipal(USER);
        thread_principal.set(user);
        thread_credential.set(PASSWORD);
        // Spawn a thread 
        Thread t = new Thread(new Child(), "testSecurityPropagation");
        // See that changing the current thread info is not seen by children threads
        thread_principal.set(new SimplePrincipal("other"));
        thread_credential.set("otherpass");
        t.start();
        t.join();
    }

    static class Child implements Runnable
    {
        public void run()
        {
            Thread t = Thread.currentThread();
            System.out.println("Child.run begin, t="+t);
            if( t.getName().equals("testSecurityPropagation") )
            {
                SimplePrincipal user = (SimplePrincipal) thread_principal.get();
                String password = (String) thread_credential.get();
                if( user.getName().equals(USER) == false )
                    fail("Thread user != "+USER);
                if( password.equals(PASSWORD) == false )
                    fail("Thread password != "+PASSWORD);
            }
            System.out.println("Child.run end, t="+t);
        }
    }

    public static void main(java.lang.String[] args)
    {
        System.setErr(System.out);
        TestSuite suite = new TestSuite(ThreadLocalTestCase.class);
        junit.textui.TestRunner.run(suite);
    }
    
}
