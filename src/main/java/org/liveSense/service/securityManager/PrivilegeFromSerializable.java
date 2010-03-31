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
import java.util.Iterator;
import javax.jcr.RepositoryException;
import javax.jcr.security.AccessControlException;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.Privilege;

/**
 *
 * @author Robert Csakany (robson@semmi.se)
 * @created Feb 26, 2010
 */
public class PrivilegeFromSerializable implements Privilege {

	SerializablePrivilege privilege;


	static Privilege[] fromSerializableArray(AccessControlManager util, SerializablePrivilege[] privileges) throws AccessControlException, RepositoryException {
		/*
		ArrayList<Privilege> ret = new ArrayList<Privilege>();
		for (int i = 0; i < privileges.length; i++) {
			ret.add(util.privilegeFromName(privileges[i].getName()));
		}
		return (Privilege[]) ret.toArray();
		 *
		 */
		Privilege[] ret = new Privilege[privileges.length];
		for (int i = 0; i < privileges.length; i++) {
			ret[i] = util.privilegeFromName(privileges[i].getName());
		}
		return ret;
	}

	public PrivilegeFromSerializable(SerializablePrivilege privilege) {
		this.privilege = privilege;
	}


	public String getName() {
		return privilege.getName();
	}

	public boolean isAbstract() {
		return privilege.isAbstract();
	}

	public boolean isAggregate() {
		return privilege.isAggregate();
	}

	public Privilege[] getDeclaredAggregatePrivileges() {
		ArrayList<PrivilegeFromSerializable> ret = new ArrayList<PrivilegeFromSerializable>();
		Iterator<SerializablePrivilege> iter = privilege.declaredAggregatePrivileges.iterator();
		while (iter.hasNext()) {
			ret.add(new PrivilegeFromSerializable(iter.next()));
		}
		PrivilegeFromSerializable[] retArr = new PrivilegeFromSerializable[ret.size()];
		System.arraycopy(ret.toArray(), 0, retArr, 0, ret.size());

		return retArr;
	}

	public Privilege[] getAggregatePrivileges() {
		ArrayList<PrivilegeFromSerializable> ret = new ArrayList<PrivilegeFromSerializable>();
		Iterator<SerializablePrivilege> iter = privilege.aggregatePrivileges.iterator();
		while (iter.hasNext()) {
			ret.add(new PrivilegeFromSerializable(iter.next()));
		}
		PrivilegeFromSerializable[] retArr = new PrivilegeFromSerializable[ret.size()];
		System.arraycopy(ret.toArray(), 0, retArr, 0, ret.size());

		return retArr;
	}

}
