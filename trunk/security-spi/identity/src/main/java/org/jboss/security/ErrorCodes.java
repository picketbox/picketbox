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
package org.jboss.security;

/**
 * Error Codes for PicketBox Project
 * @author Anil Saldhana
 * @since Oct 27, 2011
 */
public interface ErrorCodes 
{
	String ILLEGAL_ARGUMENT = "PB00001 : Illegal Argument :";
	
	String NOT_YET_IMPLEMENTED = "PB00002: Not Yet Implemented:";
	
	String FAILED_TO_OBTAIN_SHA = "PB00003: Failed to obtain SHA MessageDigest:";
	
	String FAILED_TO_CREATE_SECRET_KEY_SPEC = "PB00004: Failed to create SecretKeySpec from session key, msg=";
	
	String UNEXPECTED_EXCEPTION_CREATE_SECRET_KEY_SPEC = "PB00005: Unexpected exception during SecretKeySpec creation, msg=";
	
	String FAILED_TO_CREATE_SEALEDOBJECT = "PB00006: Failed to create SealedObject, msg=";
	
	String KEY_IS_NOT_STRING = "PB00007: key is not a String";
	
	String UNRECOGNIZED_CALLBACK = "PB00008: Unrecognized Callback";
	
	String FAILED_TO_OBTAIN_USERNAME = "PB00009: Failed to obtain username, ioe=";
	
	String FAILED_TO_OBTAIN_PASSWORD = "PB00010: Failed to obtain password, ioe=";
	
	String SECURITY_CONTEXT_NULL = "PB00011: Security context is null";
	
	String UNSUPPORTED_ALGO = "PB00012: Unsupported algorigthm: ";
	
	String UNSUPPORTED_QOP = "PB00013: Unsupported qop=";
	
	String NULL_ARGUMENT = "PB00014: Null Argument:";
	
	String NULL_VALUE = "PB00015: Null Value:";
	
	String WRONG_TYPE = "PB00016: Wrong Type:";
	
	String MISMATCH_SIZE = "PB00017: Mismatch in size:";
	
	String CANNOT_REGISTER_PROVIDER = "PB00018: Cannot register Provider:";
	
	String PROCESSING_FAILED = "PB00019: Processing Failed:";
	
	String WRONG_VALUE = "PB00020: Wrong Value:";
	
	String INVALID_OPERATION = "PB00021: Invalid Operation:";
	
	String MISSING_VALUE = "PB00022: Missing Value:";

	String MISSING_FILE = "PB00023: Missing File:";
	
	String ACCESS_DENIED = "PB00024: Access Denied:";
	
	String UNSUPPORTED_TYPE = "PB00025: Unsupported Type:";

	String WRONG_FORMAT = "PB00026: Wrong Format:";

	String VAULT_MISMATCH = "PB00027: Vault Mismatch:";

	String VALUE_MISMATCH = "PB00028: Match of values failed:";
}