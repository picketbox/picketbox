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
package org.jboss.test.authentication.cbh;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
 
import org.jboss.security.auth.callback.DatabaseCallbackHandler;
import org.junit.Before;
import org.junit.Test; 

/**
 * Unit test the {@code DatabaseCallbackHandler}
 * @author Anil Saldhana
 * @since Oct 31, 2011
 */
public class DatabaseCallbackHandlerUnitTestCase 
{
	String driverName = "org.hsqldb.jdbc.JDBCDriver";
	String connectionURL = "jdbc:hsqldb:mem:unit_test";
	
	String createTableSql = "CREATE TABLE Principals (PrincipalID VARCHAR(10),Password VARCHAR(10));" ;
	
	String query = "select PrincipalID from Principals";
	
	@Before
	public void setup() throws Exception
	{ 
		Connection conn = getConnection();
		assertTrue(conn != null);
		
		Statement stat = conn.createStatement();
		stat.executeUpdate("DROP TABLE IF EXISTS Principals;");
		stat.executeUpdate(createTableSql); 
		
		PreparedStatement prep = conn.prepareStatement(
			      "insert into Principals values (?,?);");
		
		prep.setString(1, "anil");
		prep.setString(2, "anilpass");
		prep.addBatch();
		
		prep.setString(1, "steve");
		prep.setString(2, "jobs");
		prep.addBatch();
		
		prep.executeBatch();
		prep.close();
	}
	
	@Test
	public void testCBH() throws Exception
	{
		query();
		DatabaseCallbackHandler cbh = new DatabaseCallbackHandler();
		
		Map<String,String> map = new HashMap<String,String>();
        map.put(DatabaseCallbackHandler.DB_DRIVERNAME, driverName);
        map.put(DatabaseCallbackHandler.CONNECTION_URL, connectionURL);
        map.put(DatabaseCallbackHandler.DB_USERNAME, "sa");
        map.put(DatabaseCallbackHandler.DB_USERPASS, "");
        
        cbh.setConfiguration(map);
        
		NameCallback ncb = new NameCallback("Enter");
		ncb.setName("anil");
		
		PasswordCallback pcb = new PasswordCallback("Enter", false);
		cbh.handle(new Callback[] {ncb,pcb} );
		
		assertEquals("anilpass", new String(pcb.getPassword()));
	}
	
	private void query() throws Exception
	{
		Connection conn = getConnection();
		Statement stmt = conn.createStatement();
		ResultSet rs = stmt.executeQuery(query);
		while (rs.next()) 
		{
			String user = rs.getString(1);
			if(!(user.equals("anil") || user.equals("steve")))
			{
				throw new RuntimeException("wrong user");
			} 
		}
	}
	
	private Connection getConnection() throws Exception
	{
		Class.forName(driverName);
		Connection conn = DriverManager.getConnection(connectionURL, "sa", "");
		assertTrue(conn != null);
		
		conn.setAutoCommit(true);
		return conn;
	}
}