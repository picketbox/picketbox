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
package org.jboss.test.security.config;

import org.jboss.security.config.PolicyConfig;
import org.jboss.xb.binding.Unmarshaller;
import org.jboss.xb.binding.UnmarshallerFactory;
import org.jboss.xb.binding.sunday.unmarshalling.SchemaBinding;
import org.jboss.xb.binding.sunday.unmarshalling.XsdBinder;

//$Id$

/**
 *  Validate JBossXB SchemaBinding
 *  @author Anil.Saldhana@redhat.com
 *  @since  Aug 14, 2007 
 *  @version $Revision$
 */
public class JBossXBSchemaBindingUnitTestCase extends SecurityConfigurationUnitTestCase
{ 
   
   public JBossXBSchemaBindingUnitTestCase(String name)
   {
      super(name); 
   }

   protected void setUp() throws Exception
   {
      super.setUp();
      
      // **** UNCOMMENT TO ENABLE TRACE ***
      //this.enableTrace("org.jboss.xb.binding.sunday.unmarshalling.XsdBinder");
      
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      SchemaBinding schema = XsdBinder.bind(tcl.getResourceAsStream(schemaFile), null);      
      Unmarshaller unmarshaller = UnmarshallerFactory.newInstance().newUnmarshaller();
      config = (PolicyConfig) unmarshaller.unmarshal(tcl.getResourceAsStream(xmlFile), schema);
      assertNotNull(config); 
   } 
}
