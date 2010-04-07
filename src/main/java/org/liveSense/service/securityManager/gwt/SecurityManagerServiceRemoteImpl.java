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

/**
 *
 * @author Robert Csakany (robson@semmi.se)
 * @created Feb 12, 2010
 */
package org.liveSense.service.securityManager.gwt;

import java.security.Principal;
import java.util.List;
import java.util.Map;
import javax.jcr.LoginException;
import javax.jcr.RepositoryException;
import org.apache.sling.jcr.api.SlingRepository;
import org.liveSense.service.securityManager.AccessRights;
import org.liveSense.service.securityManager.SerializablePrivilege;
import org.liveSense.service.securityManager.exceptions.GroupAlreadyExistsException;
import org.liveSense.service.securityManager.exceptions.GroupNotExistsException;
import org.liveSense.service.securityManager.exceptions.PrincipalIsNotGroupException;
import org.liveSense.service.securityManager.exceptions.PrincipalIsNotUserException;
import org.liveSense.service.securityManager.exceptions.PrincipalNotExistsException;
import org.liveSense.service.securityManager.exceptions.UserAlreadyExistsException;
import org.liveSense.service.securityManager.exceptions.UserNotExistsException;
import org.liveSense.servlet.gwtrpc.SlingRemoteServiceServlet;
import org.liveSense.utils.GenericValue;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.Session;
import javax.jcr.Credentials;
import org.apache.sling.commons.osgi.OsgiUtil;
import org.liveSense.service.securityManager.SecurityManagerService;
import org.liveSense.service.securityManager.exceptions.AccessDeniedException;
import org.liveSense.service.securityManager.exceptions.InternalException;

/**
 * This class implements a servlet-based RPC remote service for handling RPC calls from the GWT client application.
 * <p/>
 * It registers as an OSGi service and component, under the <code>javax.servlet.Servlet</code> interface. It thus
 * acts as a servlet, registered under the path specified  by the <code>sling.servlet.paths</code> @scr.property.
 * The path under which the servlet is registered must correspond to the GWT module's base url.
 * <p/>
 * The NotesServiceImpl class handles the creation, retrieval and deletion of {@link Note}s, as POJOs and as
 * <code>javax.jcr.Node</code>s in the repository.
 * <p/>
 * The class is an implementation of the <code>SlingRemoteServiceServlet</code> and is as such able to handle
 * GWT RPC calls in a Sling environment. The servlet must be registered with the GWT client application in the
 * <code>Notes.gwt.xml</code> module configuration file.
 *
 * @scr.component metatype="true"
 * @scr.service interface="javax.servlet.Servlet"
 * @scr.property name="sling.servlet.paths" values="/gwt/org.liveSense.service/securityManagerService"
 */
public class SecurityManagerServiceRemoteImpl extends SlingRemoteServiceServlet implements SecurityManagerServiceRemote {

    /**
     * The logging facility.
     */
    private static final Logger log = LoggerFactory.getLogger(SecurityManagerServiceRemoteImpl.class);


    /**
     * This is the <code>SlingRepository</code> as provided by the Sling environment. It is used for repository
     * access/operations.
     *
     * @scr.reference
     */
    private SlingRepository repository;

	/**
	 * @scr.reference
	 */
	private SecurityManagerService securityManager;

	/**
	 * @scr.property    label="%allowedUsers.name"
	 *                  description="%allowedUsers.description"
	 *                  valueRef="DEFAULT_ALLOWED_USERS"
	 */
	public static final String PARAM_ALLOWED_USERS = "allowedUsers";
	public static final String[] DEFAULT_ALLOWED_USERS = new String[]{"admin"};
	private String[] allowedUsers = DEFAULT_ALLOWED_USERS;

    /**
     * This is the OSGi component/service activation method. It initializes this service.
     *
     * @param context The OSGi context provided by the activator.
     */
    protected void activate(ComponentContext context) {
        /**
         * GWT normally uses Thread.getCurrentThread().getContextClassLoader() as its class loader. This is illegal
         * in the OSGi environment, as GWT then cannot access the service implementation classes of this bundle
         * during an RPC call. As such we have explicitly hand over our bundle's class loader to GWT. For this purpose
         * this class extends <code>SlingRemoteServiceServlet</code> instead of only GWT's <code>RemoteServiceServlet</code>.
         * The <code>SlingRemoteServiceServlet</code> has been extended to set a correct classloader and to provide
         * resources via bundles.
         */

		
        super.setClassLoader(context.getBundleContext().getBundle().getClass().getClassLoader());
        super.setBundle(context.getBundleContext().getBundle());

		// Setting up allowedUsers
		String[] allowedUsersNew = OsgiUtil.toStringArray(context.getProperties().get(PARAM_ALLOWED_USERS), DEFAULT_ALLOWED_USERS);
		boolean allowedUsersChanged = false;
		if (allowedUsersNew.length != this.allowedUsers.length) {
			allowedUsersChanged = true;
		} else {
			for (int i = 0; i < allowedUsersNew.length; i++) {
				if (!allowedUsersNew[i].equals(this.allowedUsers[i])) {
					allowedUsersChanged = true;
				}
			}
			if (allowedUsersChanged) {
				StringBuffer allowedUsersValueList = new StringBuffer();
				StringBuffer allowedUsersNewValueList = new StringBuffer();

				for (int i = 0; i < allowedUsersNew.length; i++) {
					if (i != 0) {
						allowedUsersNewValueList.append(", ");
					}
					allowedUsersNewValueList.append(allowedUsersNew[i].toString());
				}

				for (int i = 0; i < allowedUsers.length; i++) {
					if (i != 0) {
						allowedUsersValueList.append(", ");
					}
					allowedUsersValueList.append(allowedUsers[i].toString());
				}
				log.info("Setting new allowedUsers: {}) (was: {})", allowedUsersNewValueList.toString(), allowedUsersValueList.toString());
				this.allowedUsers = allowedUsersNew;
			}
		}


    
		log.info("activate: initialized and provided classloader {} to GWT.", context.getBundleContext().getBundle().getClass().getClassLoader());
	}



	private boolean isAllowed() throws AccessDeniedException {
		String user = this.getThreadLocalRequest().getRemoteUser();
		for (int i = 0; i < allowedUsers.length; i++) {
			if (user.equals(allowedUsers[i])) return true;
		}
		throw new AccessDeniedException("Access denied for user: "+user);
	}

	private Session getUserSession() throws AccessDeniedException, InternalException {
		String user = this.getThreadLocalRequest().getRemoteUser();
		try {
			Credentials creds = (Credentials) this.getThreadLocalRequest().getAttribute("AUTHENTICATION_CREDENTIALS");
			return repository.login(creds);
		} catch (LoginException ex) {
			throw new AccessDeniedException("Access denied for user: "+user, ex);
		} catch (RepositoryException ex) {
			throw new InternalException("Repository exception",ex);
		}
	}

	public void addGroup(String groupName, Map<String, Object> properties) throws GroupAlreadyExistsException, InternalException, AccessDeniedException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public void addUser(String userName, String password, Map<String, Object> properties) throws UserAlreadyExistsException, InternalException, AccessDeniedException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public boolean canAddChildren(String absPath) throws AccessDeniedException, InternalException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public boolean canDelete(String absPath) throws AccessDeniedException, InternalException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public boolean canDeleteAuthorizable(String principalID) throws AccessDeniedException, InternalException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public boolean canDeleteChildren(String absPath) throws AccessDeniedException, InternalException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public boolean canModifyAccessControl(String absPath) throws AccessDeniedException, InternalException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public boolean canModifyProperties(String absPath) throws AccessDeniedException, InternalException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public boolean canReadAccessControl(String absPath) throws AccessDeniedException, InternalException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public boolean canUpdateAuthorizable(String principalID) throws AccessDeniedException, InternalException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public void changePasswordByName(String userName, String password) throws UserNotExistsException, PrincipalIsNotUserException, InternalException, AccessDeniedException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public void deleteGroupByName(String groupName) throws GroupNotExistsException, InternalException, PrincipalIsNotGroupException, AccessDeniedException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public void deleteUserByName(String userName) throws UserNotExistsException, InternalException, PrincipalIsNotUserException, AccessDeniedException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public AccessRights getAclByName(String principalId, String absPath) throws InternalException, AccessDeniedException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public Map<String, AccessRights> getDeclaredAccessRights(String absPath) throws InternalException, AccessDeniedException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public AccessRights getDeclaredAccessRightsForPrincipal(String absPath, String principalId) throws InternalException, AccessDeniedException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public List<String> getDeclaredMemberOfByName(String principal) throws PrincipalNotExistsException, InternalException, AccessDeniedException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public List<String> getDeclaredMembersByName(String groupName) throws InternalException, PrincipalIsNotGroupException, GroupNotExistsException, AccessDeniedException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public Map<Principal, AccessRights> getEffectiveAccessRights(String absPath) throws InternalException, AccessDeniedException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public AccessRights getEffectiveAccessRightsForPrincipal(String absPath, String principalId) throws InternalException, AccessDeniedException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public List<String> getEffectiveMemberOfByName(String principal) throws PrincipalNotExistsException, InternalException, AccessDeniedException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public List<String> getEffectiveMembersByName(String groupName) throws InternalException, PrincipalIsNotGroupException, GroupNotExistsException, AccessDeniedException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public Map<String, GenericValue> getPrincipalPropertiesByName(String principal) throws PrincipalNotExistsException, InternalException, AccessDeniedException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public SerializablePrivilege[] getSupportedPrivileges(String absPath) throws InternalException, AccessDeniedException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public SerializablePrivilege[] getSupportedPrivilegesAdmin(String absPath) throws InternalException, AccessDeniedException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public void modifyPrincipalPropertiesByName(String principal, Map<String, GenericValue> properties) throws UserNotExistsException, InternalException, PrincipalIsNotUserException, AccessDeniedException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public void setAclByName(String principal, String path, AccessRights privileges) throws InternalException, PrincipalNotExistsException, AccessDeniedException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

/*
	public void setAclByName(String principal, String path, AccessRights privileges) throws InternalException, PrincipalNotExistsException, AccessDeniedException {
		if (isAllowed()) securityManager.setAclByName(principal, path, privileges);
	}

	public void modifyPrincipalPropertiesByName(String principal, Map<String, GenericValue> properties) throws UserNotExistsException, InternalException, PrincipalIsNotUserException, AccessDeniedException {
		if (isAllowed()) securityManager.modifyPrincipalPropertiesByName(principal, properties);
	}

	public SerializablePrivilege[] getSupportedPrivileges(String absPath) throws InternalException, AccessDeniedException {
		if (isAllowed()) return securityManager.getSupportedPrivileges(absPath);
		return null;
	}

	public SerializablePrivilege[] getSupportedPrivilegesAdmin(String absPath) throws InternalException, AccessDeniedException {
		if (isAllowed()) return securityManager.getSupportedPrivileges(getUserSession(), absPath);
		return null;
	}

	public Map<String, GenericValue> getPrincipalPropertiesByName(String principal) throws PrincipalNotExistsException, InternalException, AccessDeniedException {
		if (isAllowed()) return securityManager.getPrincipalPropertiesByName(principal);
		return null;
	}

	public List<String> getEffectiveMembersByName(String groupName) throws InternalException, PrincipalIsNotGroupException, GroupNotExistsException, AccessDeniedException {
		if (isAllowed()) {
			List<String> ret = new ArrayList<String>();
			List<Authorizable> members = securityManager.getEffectiveMembersByName(groupName);
			for (Authorizable authorizable : members) {
				try {
					ret.add(authorizable.getID());
				} catch (RepositoryException ex) {
					throw new InternalException("Repository exception", ex);
				}
			}
			return ret;
		}
		return null;
	}

	public List<String> getEffectiveMemberOfByName(String principal) throws PrincipalNotExistsException, InternalException, AccessDeniedException {
		if (isAllowed()) {
			List<String> ret = new ArrayList<String>();
			List<Group> members = securityManager.getEffectiveMemberOfByName(principal);
			for (Group authorizable : members) {
				try {
					ret.add(authorizable.getID());
				} catch (RepositoryException ex) {
					throw new InternalException("Repository exception", ex);
				}
			}
			return ret;
		}
		return null;
	}

	public AccessRights getEffectiveAccessRightsForPrincipal(String absPath, String principalId) throws InternalException, AccessDeniedException {
		return securityManager.getEffectiveAccessRightsForPrincipal(getUserSession(), absPath, principalId);
	}

	public Map<Principal, AccessRights> getEffectiveAccessRights(String absPath) throws InternalException, AccessDeniedException {
		return securityManager.getEffectiveAccessRights(getUserSession(), absPath);
	}

	public List<String> getDeclaredMembersByName(String groupName) throws InternalException, PrincipalIsNotGroupException, GroupNotExistsException, AccessDeniedException {
		if (isAllowed()) {
			List<String> ret = new ArrayList<String>();
			List<Authorizable> members = securityManager.getDeclaredMembersByName(groupName);
			for (Authorizable authorizable : members) {
				try {
					ret.add(authorizable.getID());
				} catch (RepositoryException ex) {
					throw new InternalException("Repository exception", ex);
				}
			}
			return ret;
		}
		return null;
	}

	public List<String> getDeclaredMemberOfByName(String principal) throws PrincipalNotExistsException, InternalException, AccessDeniedException {
		if (isAllowed()) {
			List<String> ret = new ArrayList<String>();
			List<Group> members = securityManager.getDeclaredMemberOfByName(principal);
			for (Group authorizable : members) {
				try {
					ret.add(authorizable.getID());
				} catch (RepositoryException ex) {
					throw new InternalException("Repository exception", ex);
				}
			}
			return ret;
		}
		return null;
	}

	public AccessRights getDeclaredAccessRightsForPrincipal(String absPath, String principalId) throws InternalException, AccessDeniedException {
		if (isAllowed()) return securityManager.getDeclaredAccessRightsForPrincipal(absPath, principalId);
		return null;
	}

	public Map<String, AccessRights> getDeclaredAccessRights(String absPath) throws InternalException, AccessDeniedException {
		Map<Principal, AccessRights> rights = securityManager.getDeclaredAccessRights(getUserSession(), absPath);
		Map<String, AccessRights> ret = new HashMap<String, AccessRights>();
		for (Principal principal : rights.keySet()) {
			ret.put(principal.getName(), rights.get(principal));
		}
		return ret;
	}

	public AccessRights getAclByName(String principalId, String absPath) throws InternalException, AccessDeniedException {
		if (isAllowed()) return securityManager.getAclByName(principalId, absPath);
		return null;
	}

	public void deleteUserByName(String userName) throws UserNotExistsException, InternalException, PrincipalIsNotUserException, AccessDeniedException {
		if (isAllowed()) securityManager.deleteUserByName(userName);
	}

	public void deleteGroupByName(String groupName) throws GroupNotExistsException, InternalException, PrincipalIsNotGroupException, AccessDeniedException {
		if (isAllowed()) securityManager.deleteGroupByName(groupName);
	}

	public void changePasswordByName(String userName, String password) throws UserNotExistsException, PrincipalIsNotUserException, InternalException, AccessDeniedException {
		if(isAllowed()) securityManager.changePasswordByName(userName, password);
	}

	public boolean canUpdateAuthorizable(String principalID) throws AccessDeniedException, InternalException {
		return securityManager.canUpdateAuthorizable(getUserSession(), principalID);
	}

	public boolean canReadAccessControl(String absPath) throws AccessDeniedException, InternalException {
		return securityManager.canReadAccessControl(getUserSession(), absPath);
	}


	public boolean canModifyProperties(String absPath) throws AccessDeniedException, InternalException {
		return securityManager.canModifyProperties(getUserSession(), absPath);
	}

	public boolean canModifyAccessControl(String absPath) throws AccessDeniedException, InternalException {
		return securityManager.canModifyAccessControl(getUserSession(), absPath);
	}

	public boolean canDeleteChildren(String absPath) throws AccessDeniedException, InternalException {
		return securityManager.canDeleteChildren(getUserSession(), absPath);
	}

	public boolean canDeleteAuthorizable(String principalID) throws AccessDeniedException, InternalException {
		return securityManager.canDeleteAuthorizable(getUserSession(), principalID);
	}

	public boolean canDelete(String absPath) throws AccessDeniedException, InternalException {
		return securityManager.canDelete(getUserSession(), absPath);
	}

	public boolean canAddChildren(String absPath) throws AccessDeniedException, InternalException {
		return securityManager.canAddChildren(getUserSession(), absPath);
	}

	public void addUser(String userName, String password, Map<String, Object> properties) throws UserAlreadyExistsException, InternalException, AccessDeniedException {
		if (isAllowed()) securityManager.addUser(userName, password, properties);
	}

	public void addGroup(String groupName, Map<String, Object> properties) throws GroupAlreadyExistsException, InternalException, AccessDeniedException {
		if (isAllowed()) securityManager.addGroup(groupName, properties);
	}
*/

	
}
