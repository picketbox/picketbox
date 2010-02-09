/*
 * JBoss, the OpenSource J2EE webOS
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.jboss.security.config;

import org.jboss.security.mapping.config.MappingModuleEntry;

/**
 *  Mapping Info
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @version $Revision$
 *  @since  Aug 28, 2006
 */
public class MappingInfo extends BaseSecurityInfo<MappingModuleEntry>
{  
   public MappingInfo()
   {
      super();
   }
   
   public MappingInfo(String name)
   {
      super(name);
   }  

   public MappingModuleEntry[] getMappingModuleEntry()
   {
      SecurityManager sm = System.getSecurityManager();
      if( sm != null )
         sm.checkPermission(GET_CONFIG_ENTRY_PERM); 
      MappingModuleEntry[] entries = new MappingModuleEntry[moduleEntries.size()];
      moduleEntries.toArray(entries);
      return entries;
   }

   @Override
   protected BaseSecurityInfo<MappingModuleEntry> create(String name)
   { 
      return new MappingInfo(name);
   }    
}