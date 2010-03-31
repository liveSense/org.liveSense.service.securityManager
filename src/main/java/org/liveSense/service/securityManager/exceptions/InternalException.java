/*
 *  Copyright 2010 Robert Csakany <robson@semmi.se>.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *  under the License.
 */
package org.liveSense.service.securityManager.exceptions;

import java.io.Serializable;

/**
 *
 * @author Robert Csakany (robson@semmi.se)
 * @created Feb 12, 2010
 */
public class InternalException extends Exception implements Serializable {

	private String msg;


	public InternalException() {
		super();
	}

	public InternalException(String msg) {
		super(msg);
		this.msg = msg;
	}

	public InternalException(Throwable cause) {
		super(cause);
		this.msg = cause.getMessage();
	}

	public InternalException(String msg, Throwable cause) {
		super(msg, cause);
		this.msg = msg;
	}

	public String getMessage() {
		return msg;
	}
}
