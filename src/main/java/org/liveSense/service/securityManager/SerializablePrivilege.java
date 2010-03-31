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

import java.io.Serializable;
import java.util.ArrayList;
import javax.jcr.security.Privilege;

/**
 *
 * @author Robert Csakany (robson@semmi.se)
 * @created Feb 26, 2010
 */
public class SerializablePrivilege implements Serializable {

	public static final String	JCR_ADD_CHILD_NODES	= "{http://www.jcp.org/jcr/1.0}addChildNodes";
	public static final String	JCR_ALL = "{http://www.jcp.org/jcr/1.0}all";
	public static final String	JCR_LIFECYCLE_MANAGEMENT ="{http://www.jcp.org/jcr/1.0}lifecycleManagement";
	public static final String	JCR_LOCK_MANAGEMENT	= "{http://www.jcp.org/jcr/1.0}lockManagement";
	public static final String	JCR_MODIFY_ACCESS_CONTROL = "{http://www.jcp.org/jcr/1.0}modifyAccessControl";
	public static final String	JCR_MODIFY_PROPERTIES = "{http://www.jcp.org/jcr/1.0}modifyProperties";
	public static final String	JCR_NODE_TYPE_MANAGEMENT = "{http://www.jcp.org/jcr/1.0}nodeTypeManagement";
	public static final String	JCR_READ = "{http://www.jcp.org/jcr/1.0}read";
	public static final String	JCR_READ_ACCESS_CONTROL = "{http://www.jcp.org/jcr/1.0}readAccessControl";
	public static final String	JCR_REMOVE_CHILD_NODES = "{http://www.jcp.org/jcr/1.0}removeChildNodes";
	public static final String	JCR_REMOVE_NODE = "{http://www.jcp.org/jcr/1.0}removeNode";
	public static final String	JCR_RETENTION_MANAGEMENT = "{http://www.jcp.org/jcr/1.0}retentionManagement";
	public static final String	JCR_VERSION_MANAGEMENT = "{http://www.jcp.org/jcr/1.0}versionManagement";
	public static final String	JCR_WRITE = "{http://www.jcp.org/jcr/1.0}write";


	String name;
	boolean abstract_;
	boolean aggregate;
    ArrayList<SerializablePrivilege> declaredAggregatePrivileges = new ArrayList<SerializablePrivilege>();
	ArrayList<SerializablePrivilege> aggregatePrivileges = new ArrayList<SerializablePrivilege>();

	public static SerializablePrivilege[] fromPrivilegeArray(Privilege[] privileges) {
		SerializablePrivilege[] ret = new SerializablePrivilege[privileges.length];
		for (int i = 0; i < privileges.length; i++) {
			ret[i] = new SerializablePrivilege(privileges[i]);
		}
		return ret;
	}

	public SerializablePrivilege(String name) {
		this.name = name;
	}

	public SerializablePrivilege(Privilege privilege) {
		this.name = privilege.getName();
		this.abstract_ = privilege.isAbstract();

		Privilege[] privs = privilege.getDeclaredAggregatePrivileges();
		for (int i = 0; i < privs.length; i++) {
			declaredAggregatePrivileges.add(new SerializablePrivilege(privs[i]));

		}
		privs = privilege.getAggregatePrivileges();
		for (int i = 0; i < privs.length; i++) {
			aggregatePrivileges.add(new SerializablePrivilege(privs[i]));
		}
	}

	public boolean isAbstract() {
		return abstract_;
	}

	public void setAbstract(boolean abstract_) {
		this.abstract_ = abstract_;
	}

	public boolean isAggregate() {
		return aggregate;
	}

	public void setAggregate(boolean aggregate) {
		this.aggregate = aggregate;
	}

	public ArrayList<SerializablePrivilege> getAggregatePrivileges() {
		return aggregatePrivileges;
	}

	public void setAggregatePrivileges(ArrayList<SerializablePrivilege> aggregatePrivileges) {
		this.aggregatePrivileges = aggregatePrivileges;
	}

	public ArrayList<SerializablePrivilege> getDeclaredAggregatePrivileges() {
		return declaredAggregatePrivileges;
	}

	public void setDeclaredAggregatePrivileges(ArrayList<SerializablePrivilege> declaredAggregatePrivileges) {
		this.declaredAggregatePrivileges = declaredAggregatePrivileges;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

}
