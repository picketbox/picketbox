/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat Middleware LLC, and individual contributors
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
package org.jboss.security.test.authentication;

import java.security.Principal;
import java.util.HashMap;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import javax.security.auth.login.Configuration;

import junit.framework.TestCase;
import org.infinispan.Cache;
import org.infinispan.configuration.cache.ConfigurationBuilder;
import org.infinispan.eviction.EvictionStrategy;
import org.infinispan.eviction.EvictionType;
import org.infinispan.manager.DefaultCacheManager;
import org.infinispan.manager.EmbeddedCacheManager;
import org.jboss.security.AuthenticationManager;
import org.jboss.security.CacheableManager;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.callback.AppCallbackHandler;
import org.jboss.security.authentication.JBossCachedAuthenticationManager;
import org.jboss.security.authentication.JBossCachedAuthenticationManager.DomainInfo;

/**
 *  Unit tests for the JBossCachedAuthenticationManager.
 *  
 *  @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 *  @author Anil.Saldhana@redhat.com
 */
public class JBossCachedAuthenticationManagerUnitTestCase extends TestCase
{
   @Override
   protected void setUp() throws Exception
   {
      super.setUp();
      establishSecurityConfiguration();
   }

   public void testSecurityDomain() throws Exception
   {
      AuthenticationManager am = new JBossCachedAuthenticationManager("test1", new AppCallbackHandler("a",
            "b".toCharArray()));
      assertEquals("test1", am.getSecurityDomain());
   }

   public void testLogin() throws Exception
   {
      Principal p = new SimplePrincipal("jduke");
      AppCallbackHandler acbh = new AppCallbackHandler("jduke", "theduke".toCharArray());
      AuthenticationManager am = new JBossCachedAuthenticationManager("test", acbh);
      assertTrue(am.isValid(p, "theduke"));
   }

   public void testUnsuccessfulLogin() throws Exception
   {
      Principal p = new SimplePrincipal("jduke");
      AppCallbackHandler acbh = new AppCallbackHandler("jduke", "bad".toCharArray());
      AuthenticationManager am = new JBossCachedAuthenticationManager("test", acbh);
      assertFalse(am.isValid(p, "bad"));
   }
   
   public void testCacheHit() throws Exception
   {
      Principal p = new SimplePrincipal("jduke");
      AppCallbackHandler acbh = new AppCallbackHandler("jduke", "theduke".toCharArray());
      AuthenticationManager am = new JBossCachedAuthenticationManager("test", acbh);

      EmbeddedCacheManager cacheManager = new DefaultCacheManager();
      org.infinispan.configuration.cache.Configuration configuration = new ConfigurationBuilder()
              .expiration().maxIdle(2000)
              .build();
      cacheManager.defineConfiguration("test", configuration);

      Cache<Principal, DomainInfo> cache = cacheManager.getCache("test");
      @SuppressWarnings("unchecked")
      CacheableManager<Cache<Principal, DomainInfo>, Principal> cm = (CacheableManager<Cache<Principal, DomainInfo>, Principal>) am;
      cm.setCache(cache);
      
      assertTrue(am.isValid(p, "theduke"));
      assertTrue(cm.containsKey(p));
      Thread.sleep(1000);
      assertTrue(cm.containsKey(p));
      cacheManager.stop();
   }
   
   public void testCacheIdleTimeExpiration() throws Exception
   {
      Principal p = new SimplePrincipal("jduke");
      AppCallbackHandler acbh = new AppCallbackHandler("jduke", "theduke".toCharArray());
      AuthenticationManager am = new JBossCachedAuthenticationManager("test", acbh);
      
      EmbeddedCacheManager cacheManager = new DefaultCacheManager();
      org.infinispan.configuration.cache.Configuration configuration = new ConfigurationBuilder()
                    .expiration().maxIdle(1000)
                    .build();
            cacheManager.defineConfiguration("test", configuration);
      Cache<Principal, DomainInfo> cache = cacheManager.getCache("test");
      @SuppressWarnings("unchecked")
      CacheableManager<Cache<Principal, DomainInfo>, Principal> cm = (CacheableManager<Cache<Principal, DomainInfo>, Principal>) am;
      cm.setCache(cache);
      
      assertTrue(am.isValid(p, "theduke"));
      assertTrue(cm.containsKey(p));
      Thread.sleep(2000);
      assertFalse(cm.containsKey(p));
      cacheManager.stop();
   }
   
   public void testCacheIdleTimeUpdate() throws Exception
   {
      Principal p = new SimplePrincipal("jduke");
      AppCallbackHandler acbh = new AppCallbackHandler("jduke", "theduke".toCharArray());
      AuthenticationManager am = new JBossCachedAuthenticationManager("test", acbh);

      EmbeddedCacheManager cacheManager = new DefaultCacheManager();
      org.infinispan.configuration.cache.Configuration configuration = new ConfigurationBuilder()
              .expiration().maxIdle(2000)
              .build();
      cacheManager.defineConfiguration("test", configuration);


      Cache<Principal, DomainInfo> cache = cacheManager.getCache("test");
      @SuppressWarnings("unchecked")
      CacheableManager<Cache<Principal, DomainInfo>, Principal> cm = (CacheableManager<Cache<Principal, DomainInfo>, Principal>) am;
      cm.setCache(cache);
      
      assertTrue(am.isValid(p, "theduke"));
      assertTrue(cm.containsKey(p));
      Thread.sleep(1000);
      assertTrue(cm.containsKey(p));
      Thread.sleep(1000);
      assertTrue(cm.containsKey(p));
      Thread.sleep(1000);
      assertTrue(cm.containsKey(p));
      Thread.sleep(3000);
      assertFalse(cm.containsKey(p));
      cacheManager.stop();
   }

   public void testCacheLifespanExpiration() throws Exception
   {
      Principal p = new SimplePrincipal("jduke");
      AppCallbackHandler acbh = new AppCallbackHandler("jduke", "theduke".toCharArray());
      AuthenticationManager am = new JBossCachedAuthenticationManager("test", acbh);
      
      EmbeddedCacheManager cacheManager = new DefaultCacheManager();
      org.infinispan.configuration.cache.Configuration configuration = new ConfigurationBuilder()
              .expiration()
              .maxIdle(2000)
              .lifespan(4000)
              .build();
      cacheManager.defineConfiguration("test", configuration);

      Cache<Principal, DomainInfo> cache = cacheManager.getCache("test");
      @SuppressWarnings("unchecked")
      CacheableManager<Cache<Principal, DomainInfo>, Principal> cm = (CacheableManager<Cache<Principal, DomainInfo>, Principal>) am;
      cm.setCache(cache);
      
      assertTrue(am.isValid(p, "theduke"));
      assertTrue(cm.containsKey(p));
      Thread.sleep(1500);
      assertTrue(cm.containsKey(p));
      Thread.sleep(1500);
      assertTrue(cm.containsKey(p));
      Thread.sleep(1500);
      assertFalse(cm.containsKey(p));
      cacheManager.stop();
   }
   
   public void testCacheMaxEntriesEviction() throws Exception
   {
      Principal p = new SimplePrincipal("jduke");
      AppCallbackHandler acbh = new AppCallbackHandler("jduke", "theduke".toCharArray());
      AuthenticationManager am = new JBossCachedAuthenticationManager("test", acbh);
      
      EmbeddedCacheManager cacheManager = new DefaultCacheManager();

      //configuration.setEvictionWakeUpInterval(2000); //not sure what to migrate this to in new version

      org.infinispan.configuration.cache.Configuration configuration = new ConfigurationBuilder()
                    .expiration()
                    .maxIdle(2000)
                    .eviction().type(EvictionType.COUNT).size(2).strategy(EvictionStrategy.LRU)
                    .build();
            cacheManager.defineConfiguration("test", configuration);


      Cache<Principal, DomainInfo> cache = cacheManager.getCache("test");
      @SuppressWarnings("unchecked")
      CacheableManager<Cache<Principal, DomainInfo>, Principal> cm = (CacheableManager<Cache<Principal, DomainInfo>, Principal>) am;
      cm.setCache(cache);
      
      assertTrue(am.isValid(p, "theduke"));
      assertTrue(cm.containsKey(p));
      Principal p2 = new SimplePrincipal("scott");
      assertTrue(am.isValid(p2, "echoman"));
      assertTrue(cm.containsKey(p2));
      // we store the caller principal in the cache
       /*
      Principal p2_ = new SimplePrincipal("callerScott");
      assertTrue(cm.containsKey(p2_));
      Principal p3 = new SimplePrincipal("stark");
      assertTrue(am.isValid(p3, "javaman"));
      assertFalse(cm.containsKey(p));
      Principal p3_ = new SimplePrincipal("callerStark");
      assertTrue(cm.containsKey(p2_));
      assertTrue(cm.containsKey(p3_));
      */

      cacheManager.stop();
   }
   
   private void establishSecurityConfiguration()
   {
      SecurityActions.setJAASConfiguration((Configuration) new TestConfig());
   }

   public class TestConfig extends Configuration
   {
      @Override
      public AppConfigurationEntry[] getAppConfigurationEntry(String name)
      {
         HashMap<String, Object> map = new HashMap<String, Object>();
         map.put("usersProperties", "users.properties");
         map.put("rolesProperties", "roles.properties");
         String moduleName = "org.jboss.security.auth.spi.UsersRolesLoginModule";
         AppConfigurationEntry ace = new AppConfigurationEntry(moduleName, LoginModuleControlFlag.REQUIRED, map);

         return new AppConfigurationEntry[]
         {ace};
      }

      @Override
      public void refresh()
      {
      }
   }
}
