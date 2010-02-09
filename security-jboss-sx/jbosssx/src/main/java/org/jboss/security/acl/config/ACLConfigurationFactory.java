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

/**
 * <p>
 * Factory for {@code ACLConfiguration} objects.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class ACLConfigurationFactory
{
   private static Logger log = Logger.getLogger(ACLConfigurationFactory.class);

   private static ACLConfigParser aclParser = null;
   
   static 
   {
     //Let us try the JBossXB Parser if available
     String className = "org.jboss.security.acl.config.ACLConfigParserJBossXB";
     try
     {
        ClassLoader tcl = SecurityActions.getContextClassLoader();
        Class<?> clazz = tcl.loadClass(className);
        aclParser = (ACLConfigParser) clazz.newInstance(); 
     }
     catch(Exception e)
     {
        if(log.isTraceEnabled())
        {
           log.trace("Exception initializing ACL Config Parser based on JBossXB", e);
        }
        //Fallback to general stax based parser
        aclParser = new ACLConfigParserStax();
     }
   }
   
   /**
    * <p>
    * Creates and return an {@code ACLConfiguration} object using the specified input stream to read the ACL
    * configuration file.
    * </p>
    * 
    * @param aclConfigFileStream an {@code InputStream} that reads the contents of the ACL configuration file.
    * @return the constructed {@code ACLConfiguration} object that contains the configured ACLs.
    */
   public static ACLConfiguration getConfiguration(InputStream aclConfigFileStream)
   {
      if(aclParser == null)
         throw new IllegalStateException("ACL Config Parser is null");
      return aclParser.getConfiguration(aclConfigFileStream); 
   }
   
   /**
    * Set a new {@code ACLConfigParser}
    * @param aclParserPassed
    */
   public static void setConfigParser(ACLConfigParser aclParserPassed)
   {
      aclParser = aclParserPassed; 
   }
}