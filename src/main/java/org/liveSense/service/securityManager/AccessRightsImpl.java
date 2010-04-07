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

package org.liveSense.service.securityManager;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Set;

/**
 *
 * @author Robert Csakany (robson@semmi.se)
 * @created Feb 26, 2010
 */
public class AccessRightsImpl implements AccessRights {

		private Set<SerializablePrivilege> granted = new HashSet<SerializablePrivilege>();
		private Set<SerializablePrivilege> denied = new HashSet<SerializablePrivilege>();

		private transient static ResourceBundle resBundle = null;
		private ResourceBundle getResourceBundle(Locale locale) {
			if (resBundle == null || !resBundle.getLocale().equals(locale)) {
				resBundle = ResourceBundle.getBundle(getClass().getPackage().getName() + ".PrivilegesResources", locale);
			}
			return resBundle;
		}


		public Set<SerializablePrivilege> getGranted() {
			return granted;
		}
		public Set<SerializablePrivilege> getDenied() {
			return denied;
		}

		public String[] getGrantedAsString() {
			String[] privStr = new String[granted.size()];
			int i = 0;
			for (SerializablePrivilege privilege : granted) {
				privStr[i] = privilege.getName();
				i++;
			}
			return privStr;
		}

		public String[] getDeniedAsString() {
			String[] privStr = new String[denied.size()];
			int i = 0;
			for (SerializablePrivilege privilege : denied) {
				privStr[i] = privilege.getName();
				i++;
			}
			return privStr;
		}

		public String getPrivilegeSetDisplayName(Locale locale) {
			if (denied != null && !denied.isEmpty()) {
				//if there are any denied privileges, then this is a custom privilege set
				return getResourceBundle(locale).getString("privilegeset.custom");
			} else {
				if (granted.isEmpty()) {
					//appears to have an empty privilege set
					return getResourceBundle(locale).getString("privilegeset.none");
				}

				if (granted.size() == 1) {
					//check if the single privilege is jcr:all or jcr:read
					Iterator<SerializablePrivilege> iterator = granted.iterator();
					SerializablePrivilege next = iterator.next();
					if ("jcr:all".equals(next.getName())) {
						//full control privilege set
						return getResourceBundle(locale).getString("privilegeset.all");
					} else if ("jcr:read".equals(next.getName())) {
						//readonly privilege set
						return getResourceBundle(locale).getString("privilegeset.readonly");
					}
				} else if (granted.size() == 2) {
					//check if the two privileges are jcr:read and jcr:write
					Iterator<SerializablePrivilege> iterator = granted.iterator();
					SerializablePrivilege next = iterator.next();
					SerializablePrivilege next2 = iterator.next();
					if ( ("jcr:read".equals(next.getName()) && "jcr:write".equals(next2.getName())) ||
							("jcr:read".equals(next2.getName()) && "jcr:write".equals(next.getName())) ) {
						//read/write privileges
						return getResourceBundle(locale).getString("privilegeset.readwrite");
					}
				}

				//some other set of privileges
				return getResourceBundle(locale).getString("privilegeset.custom");
			}
		}
	}

