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

import java.security.Principal;
import java.security.acl.Group;
import java.util.Enumeration;
import java.util.HashSet;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.jboss.security.AnybodyPrincipal;
import org.jboss.security.NestableGroup;
import org.jboss.security.NobodyPrincipal;
import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;

/** Tests of the NestableGroup class.

@see org.jboss.security.NestableGroup

@author Scott.Stark@jboss.org
@version $Revision$
*/
public class NestableGroupTestCase extends TestCase
{
    static Group[] groups = {
        new SimpleGroup("roles1"),
        new SimpleGroup("roles2"),
        new SimpleGroup("roles3"),
        new SimpleGroup("roles4")
    };
    static
    {
        for(int g = 0; g < groups.length; g ++)
        {
            for(int m = 0; m < 4; m ++)
                groups[g].addMember(new SimplePrincipal("user."+g+'.'+m));
        }
    }
    static NestableGroup group = new NestableGroup("Roles");

    public NestableGroupTestCase(String testName)
    {
        super(testName);
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite();
        suite.addTest(new NestableGroupTestCase("testGetName"));
        suite.addTest(new NestableGroupTestCase("testEquals"));
        suite.addTest(new NestableGroupTestCase("testAddMember"));
        suite.addTest(new NestableGroupTestCase("testRemoveMember"));
        suite.addTest(new NestableGroupTestCase("testAnybody"));
        suite.addTest(new NestableGroupTestCase("testNobody"));

        return suite;
    }

    public void testGetName()
    {
        System.out.println("testGetName");
        assertTrue(group.getName().equals("Roles"));
    }

    public void testEquals()
    {
        System.out.println("testEquals");
        SimpleGroup CallerPrincipal = new SimpleGroup("Roles");
        assertTrue(group.equals(CallerPrincipal));
    }

    /** Test of removeMember method, of class org.jboss.security.NestableGroup. */
    public void testRemoveMember()
    {
        System.out.println("testRemoveMember");
        for(int g = groups.length -1; g >= 0; g --)
        {
            testMembers(g);
            assertTrue("Remove "+groups[g], group.removeMember(groups[g]));
        }
    }

    /** Test of addMember method, of class org.jboss.security.NestableGroup. */
    public void testAddMember()
    {
        System.out.println("testAddMember");
        for(int g = 0; g < groups.length; g ++)
        {
            Group grp = groups[g];
            group.addMember(grp);
            testMembers(g);
        }

        try
        {
            group.addMember(new SimplePrincipal("BadGroup"));
            fail("Was able to add a Principal to NestableGroup");
        }
        catch(IllegalArgumentException e)
        {
        }
    }

    public void testAnybody()
    {
        System.out.println("testAnybody");
        group.addMember(groups[0]);
        boolean isMember = group.isMember(AnybodyPrincipal.ANYBODY_PRINCIPAL);
        assertTrue("AnybodyPrincipal.isMember", isMember);
    }

    public void testNobody()
    {
        System.out.println("testNobody");
        SimpleGroup nobodyGroup = new SimpleGroup("<NOBODY>");
        SimplePrincipal nobody = new SimplePrincipal("<NOBODY>");
        nobodyGroup.addMember(nobody);
        group.addMember(nobodyGroup);
        boolean isMember = group.isMember(NobodyPrincipal.NOBODY_PRINCIPAL);
        assertTrue("NobodyPrincipal.isMember == false", isMember == false);
    }

    /** Test of members method, of class org.jboss.security.NestableGroup. */
    private void testMembers(int grpNo)
    {
        String user = "user."+grpNo+'.';
        HashSet memberSet = new HashSet();
        for(int m = 0; m < 4; m ++)
        {
            Principal p = new SimplePrincipal(user+m);
            assertTrue("Is member1, "+p, group.isMember(p));
            memberSet.add(p);
        }
        
        Enumeration members = group.members();
        while( members.hasMoreElements() )
        {
            Principal member = (Principal) members.nextElement();
            assertTrue("Is member2: "+member, memberSet.contains(member));
        }
    }

    public static void main(java.lang.String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }

}
