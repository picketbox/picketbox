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
package org.jboss.test;

import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;

//$Id$

/**
 *  Abstract JBossSX Test Base
 *  making use of the JBoss Test Setup
 *  @author Anil.Saldhana@redhat.com
 *  @since  Aug 15, 2007 
 *  @version $Revision$
 */
public class AbstractJBossSXTest extends AbstractTestCaseWithSetup
{ 
   public AbstractJBossSXTest(String name)
   {
      super(name); 
   }
   
   public static AbstractTestDelegate getDelegate(Class<?> clazz) throws Exception
   {
      return new JBossSXTestDelegate(clazz);
   }
   
   protected void setUp() throws Exception
   {
      super.setUp();
      configureLogging();
   }
   
   public SecurityContext getSecurityContext()
   {
      return SecurityContextAssociation.getSecurityContext();
   }
   
   public void setSecurityContext(SecurityContext sc)
   {
      SecurityContextAssociation.setSecurityContext(sc);
   }
}
