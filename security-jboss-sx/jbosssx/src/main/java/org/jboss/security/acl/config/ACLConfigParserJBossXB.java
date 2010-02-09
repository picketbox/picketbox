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
package org.jboss.security.acl.config;

import java.io.InputStream;

import org.jboss.logging.Logger;
import org.jboss.xb.binding.JBossXBException;
import org.jboss.xb.binding.Unmarshaller;
import org.jboss.xb.binding.UnmarshallerFactory;
import org.jboss.xb.binding.sunday.unmarshalling.SchemaBinding;
import org.jboss.xb.binding.sunday.unmarshalling.XsdBinder;

/**
 * A JBossXB based acl config parser
 * @author Anil.Saldhana@redhat.com
 * @since Jan 20, 2010
 */
public class ACLConfigParserJBossXB implements ACLConfigParser
{
   private static final String schemaName = "schema/jboss-acl-config_1_0.xsd";

   private static Logger log = Logger.getLogger(ACLConfigParserJBossXB.class);

   public ACLConfiguration getConfiguration(InputStream aclConfigFileStream)
   {
      ClassLoader tcl = SecurityActions.getContextClassLoader();
      SchemaBinding schema = XsdBinder.bind(tcl.getResourceAsStream(schemaName), null);
      Unmarshaller unmarshaller = UnmarshallerFactory.newInstance().newUnmarshaller();
      try
      {
         ACLConfiguration configuration = (ACLConfiguration) unmarshaller.unmarshal(aclConfigFileStream, schema);
         return configuration;
      }
      catch (JBossXBException e)
      {
         log.debug("Error parsing ACL configuration file", e);
         throw new RuntimeException(e);
      }
   }
}