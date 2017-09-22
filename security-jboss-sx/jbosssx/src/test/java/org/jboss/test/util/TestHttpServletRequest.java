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
package org.jboss.test.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;

import javax.servlet.AsyncContext;
import javax.servlet.DispatcherType;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpUpgradeHandler;
import javax.servlet.http.Part;

//$Id$

/**
 *  Test Http Servlet Request 
 *  @author Anil.Saldhana@redhat.com
 *  @since  May 8, 2007 
 *  @version $Revision$
 */
public class TestHttpServletRequest implements HttpServletRequest
{
   private Principal p = null;
   private String uri;
   private String meth;
   
   private Map<String,String[]> parameterMap = new HashMap<>();
   
   public TestHttpServletRequest()
   {   
   }
   public TestHttpServletRequest(Principal p, String uri, String meth)
   {
      this.p = p; 
      this.uri = uri;
      this.meth = meth;
   }

   public String getAuthType()
   { 
      return null;
   }

   public String getContextPath()
   { 
      return null;
   }

   public Cookie[] getCookies()
   { 
      return null;
   }

   public long getDateHeader(String arg0)
   { 
      return 0;
   }

   public DispatcherType getDispatcherType() {
      return null;
   }

   public String getHeader(String arg0)
   { 
      return null;
   }

   public Enumeration<String> getHeaderNames()
   { 
      return null;
   }

   public Enumeration<String> getHeaders(String arg0)
   { 
      return null;
   }

   public int getIntHeader(String arg0)
   { 
      return 0;
   }

   public String getMethod()
   {  
      return meth;
   }

   public String getPathInfo()
   { 
      return null;
   }

   public String getPathTranslated()
   { 
      return null;
   }

   public String getQueryString()
   { 
      return null;
   }

   public String getRemoteUser()
   {  
      return null;
   }

   public String getRequestURI()
   { 
      return uri;
   }

   public StringBuffer getRequestURL()
   { 
      return null;
   }

   public String getRequestedSessionId()
   { 
      return null;
   }

   public String getServletPath()
   { 
      return null;
   }

   public HttpSession getSession()
   { 
      return null;
   }

   @Override
   public String changeSessionId() {
      return null;
   }

   public HttpSession getSession(boolean arg0)
   {
      return null;
   }

   public Principal getUserPrincipal()
   {
      return p;
   }

   public boolean isRequestedSessionIdFromCookie()
   {
      return false;
   }

   public boolean isRequestedSessionIdFromURL()
   {
      return false;
   }

   public boolean isRequestedSessionIdFromUrl()
   {
      return false;
   }

   @Override
   public boolean authenticate(HttpServletResponse response) throws IOException, ServletException {
      return false;
   }

   @Override
   public void login(String username, String password) throws ServletException {

   }

   @Override
   public void logout() throws ServletException {

   }

   @Override
   public Collection<Part> getParts() throws IOException, ServletException {
      return null;
   }

   @Override
   public Part getPart(String name) throws IOException, ServletException {
      return null;
   }

   public boolean isRequestedSessionIdValid()
   {
      return false;
   }

   public boolean isUserInRole(String arg0)
   {
      return false;
   }

   public Object getAttribute(String arg0)
   {
      return null;
   }

   public Enumeration<String> getAttributeNames()
   {
      return null;
   }

   public String getCharacterEncoding()
   {
      return null;
   }

   public int getContentLength()
   {
      return 0;
   }

   @Override
   public long getContentLengthLong() {
      return 0;
   }

   public String getContentType()
   {
      return null;
   }

   public ServletInputStream getInputStream() throws IOException
   {
      return null;
   }

   public String getLocalAddr()
   {
      return null;
   }

   public String getLocalName()
   {
      return null;
   }

   public int getLocalPort()
   {
      return 0;
   }

   @Override
   public ServletContext getServletContext() {
      return null;
   }

   public Locale getLocale()
   {
      return null;
   }

   public Enumeration<Locale> getLocales()
   {
      return null;
   }

   public String getParameter(String arg)
   {
      String[] parameters = parameterMap.get(arg);
      return (parameters == null || parameters.length == 0) ? null : parameters[0];
   }

   public Map<String,String[]> getParameterMap()
   {
     return parameterMap;
   }

   public Enumeration<String> getParameterNames()
   {
      return (new Vector<String>()).elements();
   }

   public String[] getParameterValues(String arg0)
   {
      return null;
   }

   public String getProtocol()
   {
      return null;
   }

   public BufferedReader getReader() throws IOException
   {
      return null;
   }

   public String getRealPath(String arg0)
   {
      return null;
   }

   public String getRemoteAddr()
   {
      return null;
   }

   public String getRemoteHost()
   {
      return null;
   }

   public int getRemotePort()
   {
      return 0;
   }

   public RequestDispatcher getRequestDispatcher(String arg0)
   {
      return null;
   }

   public String getScheme()
   {
      return null;
   }

   public String getServerName()
   {
      return null;
   }

   public int getServerPort()
   {
      return 0;
   }

   public boolean isSecure()
   {
      return false;
   }

   public void removeAttribute(String arg0)
   { 
   }

   public void setAttribute(String arg0, Object arg1)
   {  
   }

   public void setCharacterEncoding(String arg0) throws UnsupportedEncodingException
   { 
   }

   @Override
   public AsyncContext startAsync() throws IllegalStateException {
      return null;
   }

   @Override
   public AsyncContext startAsync(ServletRequest servletRequest, ServletResponse servletResponse) throws IllegalStateException {
      return null;
   }

   @Override
   public boolean isAsyncStarted() {
      return false;
   }

   @Override
   public boolean isAsyncSupported() {
      return false;
   }

   @Override
   public AsyncContext getAsyncContext() {
      return null;
   }

   @Override
   public <T extends HttpUpgradeHandler> T upgrade(Class<T> handlerClass) throws IOException, ServletException {
      return null;
   }

   //Non-standard methods
   public void setParameter( String key, String[] value )
   {
      parameterMap.put(key, value);
   }
}
