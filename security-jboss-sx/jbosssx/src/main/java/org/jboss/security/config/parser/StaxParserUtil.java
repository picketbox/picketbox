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

import java.util.Iterator;
import java.util.Set;

import javax.xml.stream.Location;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.StartElement;
 

/**
 * Utility for the stax based parser
 * 
 * @author Anil.Saldhana@redhat.com
 * @author <a href="mailto:mmoyses@redhat.com">Marcus Moyses</a>
 * @since Feb 8, 2010
 */
public class StaxParserUtil implements XMLStreamConstants
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
   
   /**
    * Get an exception reporting a missing, required XML attribute.
    *
    * @param reader the stream reader
    * @param required a set of enums whose toString method returns the attribute name
    * @return the exception
    */
   public static XMLStreamException missingRequired(final XMLStreamReader reader, final Set<?> required)
   {
      final StringBuilder b = new StringBuilder();
      Iterator<?> iterator = required.iterator();
      while (iterator.hasNext())
      {
         final Object o = iterator.next();
         b.append(o.toString());
         if (iterator.hasNext())
         {
            b.append(", ");
         }
      }
      return new XMLStreamException("Missing required attribute(s): " + b, reader.getLocation());
   }

   /**
    * Get an exception reporting an unexpected XML element.
    *
    * @param reader the stream reader
    * @return the exception
    */
   public static XMLStreamException unexpectedElement(final XMLStreamReader reader)
   {
      return new XMLStreamException("Unexpected element '" + reader.getName() + "' encountered", reader.getLocation());
   }

   /**
    * Get an exception reporting an unexpected XML attribute.
    *
    * @param reader the stream reader
    * @param index the attribute index
    * @return the exception
    */
   public static XMLStreamException unexpectedAttribute(final XMLStreamReader reader, final int index)
   {
      return new XMLStreamException("Unexpected attribute '" + reader.getAttributeName(index) + "' encountered", reader
            .getLocation());
   }

   /**
    * Consumes the remainder of the current element, throwing an {@link XMLStreamException}
    * if it contains any child elements.
    *
    * @param reader the reader
    * @throws XMLStreamException if an error occurs
    */
   public static void requireNoContent(final XMLStreamReader reader) throws XMLStreamException
   {
      if (reader.hasNext() && reader.nextTag() != END_ELEMENT)
      {
         throw unexpectedElement(reader);
      }
   }

}