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
package org.jboss.security.config.parser;

import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

/**
 * Stax based JAAS authentication configuration Parser
 * @author Anil.Saldhana@redhat.com
 * @since Jan 22, 2010
 */
public class AuthenticationConfigParser
{
   /**
    * Parse the <authentication> element
    * @param xmlEventReader
    * @return
    * @throws XMLStreamException
    */
   public Set<AppConfigurationEntry> parse(XMLEventReader xmlEventReader) throws XMLStreamException
   {
      Set<AppConfigurationEntry> entries = new LinkedHashSet<AppConfigurationEntry>();
      while(xmlEventReader.hasNext())
      {   
         XMLEvent xmlEvent = xmlEventReader.peek(); 
         
         StartElement peekedStartElement = (StartElement) xmlEvent;
         AppConfigurationEntry entry = null;
         if("login-module".equals(StaxParserUtil.getStartElementName(peekedStartElement)))
         {
            entry = this.getEntry(xmlEventReader);
         } 
         else
            break;
         entries.add(entry); 
      }
      return entries;
   }
   
   @SuppressWarnings("unchecked")
   private AppConfigurationEntry getEntry(XMLEventReader xmlEventReader) throws XMLStreamException
   {
      XMLEvent xmlEvent = xmlEventReader.nextEvent();
      Map<String, Object> options = new HashMap<String,Object>();
      
      String codeName = null;
      LoginModuleControlFlag controlFlag = LoginModuleControlFlag.REQUIRED;
      
      //We got the login-module element
      StartElement loginModuleElement = (StartElement) xmlEvent;
      //We got the login-module element
      Iterator<Attribute> attrs = loginModuleElement.getAttributes();
      while(attrs.hasNext())
      {
         Attribute attribute = attrs.next();
         
         QName attQName = attribute.getName();
         String attributeValue = StaxParserUtil.getAttributeValue(attribute);
         
         if("code".equals(attQName.getLocalPart()))
         {
            codeName = attributeValue;
         }
         else if("flag".equals(attQName.getLocalPart()))
         {
            controlFlag = getControlFlag(attributeValue);
         } 
      } 
      //See if there are options
      ModuleOptionParser moParser = new ModuleOptionParser();
      options.putAll(moParser.parse(xmlEventReader));
      
      return new AppConfigurationEntry(codeName, controlFlag, options); 
   }  
   
   private LoginModuleControlFlag getControlFlag(String flag)
   {
      if("required".equalsIgnoreCase(flag))
         return LoginModuleControlFlag.REQUIRED;
      if("sufficient".equalsIgnoreCase(flag))
         return LoginModuleControlFlag.SUFFICIENT;
      if("optional".equalsIgnoreCase(flag))
         return LoginModuleControlFlag.OPTIONAL;
      if("requisite".equalsIgnoreCase(flag))
         return LoginModuleControlFlag.REQUISITE;
      throw new RuntimeException(flag + " is not recognized");
   }
}