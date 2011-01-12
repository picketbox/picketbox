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
package org.picketbox.config;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

import javax.xml.stream.XMLStreamException;

import org.jboss.logging.Logger;
import org.jboss.security.config.parser.StaxBasedConfigParser;
import org.picketbox.exceptions.ConfigurationFileNullException;
import org.picketbox.exceptions.ConfigurationParsingException;
import org.picketbox.exceptions.ConfigurationStreamNullException;
import org.xml.sax.SAXException;

/**
 * Defines the PicketBox Configuration
 * @author Anil.Saldhana@redhat.com
 * @since Jan 22, 2010
 */
public class PicketBoxConfiguration
{ 
   private static Logger log = Logger.getLogger(PicketBoxConfiguration.class);
   
   /**
    * Load a configuration file
    * @param configFileName
    * @throws ConfigurationFileNullException if the passed file name is null
    * @throws ConfigurationParsingException parsing exception
    */
   public void load(String configFileName) throws ConfigurationFileNullException, ConfigurationParsingException
   {
      if(configFileName == null)
         throw new ConfigurationFileNullException("configFileName is null");
      InputStream configStream = loadStream(configFileName);
      load(configStream);   
   }
   
   /**
    * Load the Configuration Stream
    * @param configStream
    * @throws ConfigurationStreamNullException if the configuration stream is null
    * @throws ConfigurationParsingException if there is parsing exception
    */
   public void load(InputStream configStream) throws ConfigurationStreamNullException, ConfigurationParsingException
   {
      if(configStream == null)
         throw new ConfigurationStreamNullException("configStream is null");
      
      //Parser will parse the stream and update the JAAS Configuration 
      // set on JDK Configuration.getConfiguration and is an instance of ApplicationPolicyRegistration
      StaxBasedConfigParser parser = new StaxBasedConfigParser();
      try
      {
         parser.parse(configStream);
      }
      catch (XMLStreamException e)
      {
         throw new ConfigurationParsingException(e);
      } 
      catch(SAXException s)
      {
         throw new ConfigurationParsingException(s);
      } 
      catch(IOException i)
      {
         throw new ConfigurationParsingException(i);
      }
   }
   
   private InputStream loadStream(String configFileName)
   {
      InputStream configStream = null;

      //Try the TCCL
      try
      {
         ClassLoader tcl = SecurityActions.getContextClassLoader();
         configStream = tcl.getResourceAsStream(configFileName);  
      }
      catch(Exception e)
      { 
         if(log.isTraceEnabled())
            log.error("Exception loading " + configFileName + " as tcl resource",e);
      }
      //Try the loading class CL
      try
      {
         if(configStream == null)
            configStream = SecurityActions.getClassLoader( getClass() ).getResourceAsStream(configFileName);
      }
      catch(Exception e)
      { 
         if(log.isTraceEnabled())
            log.error("Exception loading " + configFileName + " as cl resource",e);
      }
      //Try the URL stream
      try
      {
         if(configStream == null)
         {
            URL url = new URL(configFileName);
            configStream = url.openStream();
         }
      }  
      catch(Exception e)
      { 
         if(log.isTraceEnabled())
            log.error("Exception loading " + configFileName + " as URL resource",e);
      }
      return configStream;
   }
}