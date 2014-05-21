/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2009, Red Hat Middleware LLC, and individual contributors
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
package org.jboss.test.authentication.jaas.helpers;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jboss.security.auth.spi.InputValidationException;
import org.jboss.security.auth.spi.InputValidator;

/**
 * <p>
 * A sample {@code InputValidator} that uses both pattern and blacklist checks to verify if the supplied username and
 * password are valid.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class TestInputValidator implements InputValidator
{

   // the list of invalid tokens.
   private final String[] blackList =
   {"INSERT", "INTO", "SELECT", "FROM", "WHERE", "DROP", "DATABASE", "VALUES"};

   // a username can be any word (that is, a sequence of [a-zA-Z_0-9]).
   private final Pattern usernamePattern = Pattern.compile("[\\w]*");

   // a password can be any sequence of word and punctuation characters (that is
   // [a-zA-Z_0-9!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~])
   private final Pattern passwordPattern = Pattern.compile("[\\w\\p{Punct}]*");

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.auth.spi.InputValidator#validateUsernameAndPassword(java.lang.String, java.lang.String)
    */
   public void validateUsernameAndPassword(String username, String password) throws InputValidationException
   {
      if (username == null)
         username = "";
      if (password == null)
         password = "";

      // we start with a validation using patterns.
      Matcher usernameMatcher = this.usernamePattern.matcher(username);
      Matcher passwordMatcher = this.passwordPattern.matcher(password);
      if (!usernameMatcher.matches() || !passwordMatcher.matches())
         throw new InputValidationException("Username or password does not adhere to the acceptable pattern");

      // now we proceed with a blacklist validation.
      if (matchesBlackList(username) || matchesBlackList(password))
         throw new InputValidationException("Username or password contains invalid tokens");
   }

   /**
    * <p>
    * Example of validation that uses a blacklist to prevent invalid tokens in usernames and passwords.
    * </p>
    * 
    * @param expression the username or password being validated.
    * @return {@code true} if the expression contains one of the blacklisted tokens; {@code false} otherwise.
    */
   public boolean matchesBlackList(String expression)
   {
      String exprUpperCase = expression.toUpperCase(Locale.ENGLISH);
      for (String token : this.blackList)
      {
         if (exprUpperCase.indexOf(token) != -1)
            return true;
      }
      return false;
   }
}
