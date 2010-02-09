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

import javax.xml.stream.Location;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.StartElement;
 

/**
 * Utility for the stax based parser
 * @author Anil.Saldhana@redhat.com
 * @since Feb 8, 2010
 */
public class StaxParserUtil
{  
   /**
    * Given an {@code Attribute}, get its trimmed value
    * @param attribute
    * @return
    */
   public static String getAttributeValue(Attribute attribute)
   {
      return trim(attribute.getValue());
   }
   
   /**
    * Given a {@code Location}, return a formatted string
    * [lineNum,colNum]
    * @param location
    * @return
    */
   public static String getLineColumnNumber(Location location)
   {
     StringBuilder builder = new StringBuilder("[");
     builder.append(location.getLineNumber()).append(",").append(location.getColumnNumber()).append("]");
     return builder.toString();
   }
   
   /**
    * Return the name of the start element
    * @param startElement
    * @return
    */
   public static String getStartElementName(StartElement startElement)
   {
      return trim(startElement.getName().getLocalPart());
   }
   
   /**
    * Given a string, trim it
    * @param str
    * @return
    * @throws {@code IllegalArgumentException} if the passed str is null
    */
   public static final String trim(String str)
   {
      if(str == null || str.length() == 0)
         throw new IllegalArgumentException("Input str is null");
      return str.trim();
   }
}