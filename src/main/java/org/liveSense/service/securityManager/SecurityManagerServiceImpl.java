/*
 *Copyright 2010 Robert Csakany <robson@semmi.se>.
 *
 *Licensed under the Apache License, Version 2.0 (the "License");
 *you may not use this file except in compliance with the License.
 *You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 *Unless required by applicable law or agreed to in writing, software
 *distributed under the License is distributed on an "AS IS" BASIS,
 *WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *See the License for the specific language governing permissions and
 *limitations under the License.
 *under the License.
 */
package org.liveSense.service.securityManager;

/**
 *
 * @author Robert Csakany (robson@semmi.se)
 * @created Feb 12, 2010
 */
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.jcr.Node;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.UnsupportedRepositoryOperationException;
import javax.jcr.security.AccessControlEntry;
import javax.jcr.security.AccessControlList;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.AccessControlPolicy;
import javax.jcr.security.AccessControlPolicyIterator;
import javax.jcr.security.Privilege;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.ReferencePolicy;
import org.apache.felix.scr.annotations.Service;
import org.apache.jackrabbit.api.security.principal.PrincipalManager;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.jackrabbit.core.security.principal.EveryonePrincipal;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.jcr.base.util.AccessControlUtil;
import org.liveSense.core.Configurator;
import org.liveSense.core.PasswordDigester;
import org.liveSense.core.wrapper.GenericValue;
import org.liveSense.service.securityManager.exceptions.GroupAlreadyExistsException;
import org.liveSense.service.securityManager.exceptions.GroupNotExistsException;
import org.liveSense.service.securityManager.exceptions.InternalException;
import org.liveSense.service.securityManager.exceptions.PrincipalIsNotGroupException;
import org.liveSense.service.securityManager.exceptions.PrincipalIsNotUserException;
import org.liveSense.service.securityManager.exceptions.PrincipalNotExistsException;
import org.liveSense.service.securityManager.exceptions.UserAlreadyExistsException;
import org.liveSense.service.securityManager.exceptions.UserNotExistsException;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(label="%service.name",
	description="%service.description",
	immediate=true)
@Service(value=SecurityManagerService.class)
public class SecurityManagerServiceImpl implements SecurityManagerService {

	/**
	 * default log
	 */
	private final Logger log = LoggerFactory.getLogger(SecurityManagerServiceImpl.class);
	/**
	 * The JCR Repository we access to resolve resources
	 *
	 */

	@Reference(cardinality=ReferenceCardinality.MANDATORY_UNARY, policy=ReferencePolicy.DYNAMIC)
	private SlingRepository repository;

	/**
	 * Reference to configurator
	 * 
	 */
	@Reference(cardinality=ReferenceCardinality.MANDATORY_UNARY, policy=ReferencePolicy.DYNAMIC)
	Configurator configurator;

	
	/** Returns the JCR repository used by this service. */
	@Override
	public SlingRepository getRepository() throws RepositoryException {
		if (repository == null) throw new RepositoryException("Repository is null");
		return repository;
	}

	/**
	 * Activates this component.
	 *
	 * @param componentContext The OSGi <code>ComponentContext</code> of this
	 *component.
	 */
	@Activate
	protected void activate(ComponentContext componentContext) {
		Dictionary<?, ?> props = componentContext.getProperties();
	}

	/** {@inheritDoc} */
	@Override
	public User addUser(Session session, String userName, String password, Map<String, Object> properties) throws UserAlreadyExistsException, InternalException {
		User user = null;
		try {
			UserManager userManager = AccessControlUtil.getUserManager(session);
			Authorizable authorizable = userManager.getAuthorizable(userName);

			if (authorizable != null) {
				throw new UserAlreadyExistsException(
						"A principal already exists with the requested name: "
						+ userName);
			}
			String passwordDigest = new PasswordDigester(password, configurator.getDigest(), configurator.getEncoding()).toString();
			user = userManager.createUser(userName, passwordDigest);
			//user.setProperty("jcr:Password", GenericValue.getGenericValueFromObject(passwordDigest).get());

			for (Object key : properties.keySet()) {
				if (properties.get(key) != null) {
					GenericValue val = GenericValue.getGenericValueFromObject(properties.get(key));
					if (val.isMultiValue()) {
						// 
						user.setProperty((String) key, val.getValues());
					} else {
						user.setProperty((String) key, val.get());
					}
				}
			}
		} catch (RepositoryException ex) {
			throw new InternalException("Repository exception", ex);
		} catch (IllegalArgumentException ex) {
			throw new InternalException(ex);
		} catch (NoSuchAlgorithmException ex) {
			throw new InternalException(ex);
		} catch (UnsupportedEncodingException ex) {
			throw new InternalException(ex);
		} finally {
		}
		return user;
	}

	/** {@inheritDoc} */
	@Override
	public Group addGroup(Session session, final String groupName, Map<String, Object> properties) throws GroupAlreadyExistsException, InternalException {
		Group group = null;
		try {

			UserManager userManager = AccessControlUtil.getUserManager(session);
			Authorizable authorizable = userManager.getAuthorizable(groupName);

			if (authorizable != null) {
				// Principal already exists!
				throw new GroupAlreadyExistsException(
						"A principal already exists with the requested name: "
						+ groupName);
			}
			group = userManager.createGroup(new Principal() {

				@Override
				public String getName() {
					return groupName;
				}
			});

			if (properties != null) {
				for (Object key : properties.keySet()) {
					if (properties.get(key) != null) {
						GenericValue val = GenericValue.getGenericValueFromObject(properties.get(key));
						if (val.isMultiValue()) {
							group.setProperty((String) key, val.getValues());
						} else {
							group.setProperty((String) key, val.get());
						}
					}
				}
			}

		} catch (IllegalArgumentException ex) {
			throw new InternalException(ex);
		} catch (RepositoryException ex) {
			throw new InternalException("Repository exception", ex);
		} finally {
		}
		return group;
	}

	/** {@inheritDoc} */
	@Override
	public void deleteGroupByName(Session session, String groupName) throws GroupNotExistsException,
			InternalException, PrincipalIsNotGroupException {
		Group group = null;
		try {
			UserManager userManager = AccessControlUtil.getUserManager(session);
			Authorizable authorizable = userManager.getAuthorizable(groupName);

			if (authorizable == null) {
				// Principal already exists!
				throw new GroupNotExistsException(
						"Group does not exists with the requested name: "
						+ groupName);
			}
			if (!authorizable.isGroup()) {
				throw new PrincipalIsNotGroupException("Principal is not a group: " + groupName);
			}
			authorizable.remove();
		} catch (RepositoryException e) {
						throw new InternalException("Repository exception", e);

		} finally {
		}
	}

	/** {@inheritDoc} */
	@Override
	public void deleteUserByName(Session session, String userName) throws UserNotExistsException,
			InternalException, PrincipalIsNotUserException {
		Group group = null;
		try {
			UserManager userManager = AccessControlUtil.getUserManager(session);
			Authorizable authorizable = userManager.getAuthorizable(userName);

			if (authorizable == null) {
				// Principal already exists!
				throw new UserNotExistsException(
						"User does not exists with the requested name: "
						+ userName);
			}
			if (authorizable.isGroup()) {
				throw new PrincipalIsNotUserException("Principal is not a user: " + userName);
			}
			authorizable.remove();

		} catch (RepositoryException ex) {
			throw new InternalException("Repository exception", ex);
		} finally {
		}
	}

	/** {@inheritDoc} */
	@Override
	public Group getGroupByName(Session session, String groupName) throws GroupNotExistsException,
			InternalException, PrincipalIsNotGroupException {
		Map ret = new HashMap();

		try {
			UserManager userManager = AccessControlUtil.getUserManager(session);
			Authorizable authorizable = userManager.getAuthorizable(groupName);

			if (authorizable == null) {
				throw new GroupNotExistsException("Group does not exists: " + groupName);
			}
			if (!authorizable.isGroup()) {
				throw new PrincipalIsNotGroupException("Principal is not group: " + groupName);
			} else {
				return (Group) authorizable;
			}
		} catch (RepositoryException ex) {
						throw new InternalException("Repository exception", ex);
		} finally {
		}
	}

	/** {@inheritDoc} */
	@Override
	public User getUserByName(Session session, String userName) throws UserNotExistsException,
			InternalException, PrincipalIsNotUserException {
		Map ret = new HashMap();

		try {
			UserManager userManager = AccessControlUtil.getUserManager(session);
			Authorizable authorizable = userManager.getAuthorizable(userName);

			if (authorizable == null) {
				throw new UserNotExistsException("Group does not exists: " + userName);
			}
			if (authorizable.isGroup()) {
				throw new PrincipalIsNotUserException("Principal is not user: " + userName);
			} else {
				return (User) authorizable;
			}
		} catch (RepositoryException ex) {
						throw new InternalException("Repository exception", ex);
		} finally {
		}
	}

	/** {@inheritDoc} */
	@Override
	public Authorizable getAuthorizableByName(Session session, String principal) throws PrincipalNotExistsException,
			InternalException {
		Map ret = new HashMap();

		try {
			UserManager userManager = AccessControlUtil.getUserManager(session);
			Authorizable authorizable = userManager.getAuthorizable(principal);

			if (authorizable == null) {
				throw new PrincipalNotExistsException("Principal does not exists: " + principal);
			}
			return authorizable;
		} catch (RepositoryException ex) {
						throw new InternalException("Repository exception", ex);
		} finally {
		}
	}

	/** {@inheritDoc} */
	@Override
	public void changePasswordByName(Session session, String userName, String password) throws UserNotExistsException, PrincipalIsNotUserException, InternalException {
		try {
			UserManager userManager = AccessControlUtil.getUserManager(session);
			Authorizable authorizable = userManager.getAuthorizable(userName);

			if (authorizable == null) {
				throw new UserNotExistsException(
						"User does not exists: "
						+ userName);
			}
			if (authorizable.isGroup()) {
				throw new PrincipalIsNotUserException("Principal is not user: " + userName);
			}
			User user = (User) authorizable;
			user.changePassword(password);
			user.setProperty("jcr:Password", GenericValue.getGenericValueFromObject(password).get());

		} catch (RepositoryException e) {
						throw new InternalException("Repository exception", e);
		} finally {
		}

	}

	/** {@inheritDoc} */
	@Override
	public List<Group> getEffectiveMemberOfByName(Session session, String principal) throws PrincipalNotExistsException, InternalException {
		ArrayList<Group> ret = new ArrayList<Group>();

		try {
			UserManager userManager = AccessControlUtil.getUserManager(session);
			Authorizable authorizable = userManager.getAuthorizable(principal);

			if (authorizable == null) {
				// user already exists!
				throw new PrincipalNotExistsException(
						"Principal does not exists: "
						+ principal);
			}

			Iterator<Group> iter = authorizable.memberOf();
			while (iter.hasNext()) {
				ret.add(iter.next());
			}

		} catch (RepositoryException e) {
						throw new InternalException("Repository exception", e);

		} finally {
		}
		return ret;
	}

	/** {@inheritDoc} */
	@Override
	public List<Group> getDeclaredMemberOfByName(Session session, String principal) throws PrincipalNotExistsException, InternalException {
		ArrayList<Group> ret = new ArrayList<Group>();

		try {
			UserManager userManager = AccessControlUtil.getUserManager(session);
			Authorizable authorizable = userManager.getAuthorizable(principal);

			if (authorizable == null) {
				// user already exists!
				throw new PrincipalNotExistsException(
						"Principal does not exists: "
						+ principal);
			}

			Iterator<Group> iter = authorizable.declaredMemberOf();
			while (iter.hasNext()) {
				ret.add(iter.next());
			}

		} catch (RepositoryException e) {
						throw new InternalException("Repository exception", e);

		} finally {
		}
		return ret;
	}

	/** {@inheritDoc} */
	@Override
	public List<Authorizable> getEffectiveMembersByName(Session session, String groupName) throws InternalException, PrincipalIsNotGroupException, GroupNotExistsException {
		List<Authorizable> ret = new ArrayList<Authorizable>();

		try {
			UserManager userManager = AccessControlUtil.getUserManager(session);
			Authorizable authorizable = userManager.getAuthorizable(groupName);

			if (authorizable == null) {
				// user already exists!
				throw new GroupNotExistsException(
						"Group does not exists: "
						+ groupName);
			}
			if (!authorizable.isGroup()) {
				throw new PrincipalIsNotGroupException("Principal is not a group: " + groupName);
			}

			Iterator iter = ((Group) authorizable).getMembers();
			while (iter.hasNext()) {
				ret.add(authorizable);
			}

		} catch (RepositoryException e) {
						throw new InternalException("Repository exception", e);
		} finally {
		}
		return ret;
	}

	/** {@inheritDoc} */
	@Override
	public List<Authorizable> getDeclaredMembersByName(Session session, String groupName) throws InternalException, PrincipalIsNotGroupException, GroupNotExistsException {
		List<Authorizable> ret = new ArrayList<Authorizable>();

		try {
			UserManager userManager = AccessControlUtil.getUserManager(session);
			Authorizable authorizable = userManager.getAuthorizable(groupName);

			if (authorizable == null) {
				throw new GroupNotExistsException(
						"Group does not exists: "
						+ groupName);
			}
			if (!authorizable.isGroup()) {
				throw new PrincipalIsNotGroupException("Principal is not a group: " + groupName);
			}

			Iterator iter = ((Group) authorizable).getDeclaredMembers();
			while (iter.hasNext()) {
				ret.add(authorizable);
			}

		} catch (RepositoryException e) {
						throw new InternalException("Repository exception", e);
		} finally {
		}
		return ret;
	}

	/** {@inheritDoc} */
	@Override
	public Map<String, GenericValue> getPrincipalPropertiesByName(Session session, String principal) throws PrincipalNotExistsException, InternalException {
		Map<String, GenericValue> ret = new HashMap<String, GenericValue>();

		try {
			UserManager userManager = AccessControlUtil.getUserManager(session);
			Authorizable authorizable = userManager.getAuthorizable(principal);

			if (authorizable == null) {
				throw new PrincipalNotExistsException("Principal does not exists: " + principal);
			}
			Iterator iter = authorizable.getPropertyNames();
			while (iter.hasNext()) {
				String key = (String) iter.next();
				GenericValue value = GenericValue.getGenericValueFromObject(authorizable.getProperty(key));
				ret.put(key, value);
			}
		} catch (RepositoryException e) {
						throw new InternalException("Repository exception", e);
		} finally {
		}
		return ret;
	}

	/** {@inheritDoc} */
	@Override
	public void modifyPrincipalPropertiesByName(Session session, String principal, Map<String, GenericValue> properties)
			throws UserNotExistsException, InternalException,
			PrincipalIsNotUserException {
		// TODO Implementing
	}

	/** {@inheritDoc} */
	@Override
	public SerializablePrivilege[] getSupportedPrivileges(Node node) throws InternalException {
		try {
			return getSupportedPrivileges(node.getSession(), node.getPath());
		} catch (RepositoryException ex) {
			throw new InternalException("Repository exception", ex);
		}
	}

	/** {@inheritDoc} */
	@Override
	public SerializablePrivilege[] getSupportedPrivileges(Session session, String absPath) throws InternalException {
		try {
			AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);
			SerializablePrivilege[] supportedPrivileges = SerializablePrivilege.fromPrivilegeArray(accessControlManager.getSupportedPrivileges(absPath));
			return supportedPrivileges;
		} catch (UnsupportedRepositoryOperationException ex) {
			throw new InternalException("Unsupported operation: "+absPath, ex);
		} catch (RepositoryException ex) {
			throw new InternalException("Repository exception: "+absPath, ex);
		}
	}


	/** {@inheritDoc} */
	@Override
	public Map<Principal, AccessRights> getDeclaredAccessRights(Node node) throws InternalException {
		Map<Principal, AccessRights> accessRights;
		try {
			accessRights = getDeclaredAccessRights(node.getSession(), node.getPath());
		} catch (RepositoryException ex) {
			throw new InternalException("Repository exception", ex);
		}
		return accessRights;
	}

	/** {@inheritDoc} */
	@Override
	public Map<Principal, AccessRights> getDeclaredAccessRights(Session session, String absPath) throws InternalException {
		try {
			Map<Principal, AccessRights> accessMap = new LinkedHashMap<Principal, AccessRights>();
			AccessControlEntry[] entries = getDeclaredAccessControlEntries(session, absPath);
			if (entries != null) {
				for (AccessControlEntry ace : entries) {
					Principal principal = ace.getPrincipal();
					AccessRights accessPrivleges = accessMap.get(principal);
					if (accessPrivleges == null) {
						accessPrivleges = new AccessRightsImpl();
						accessMap.put(principal, accessPrivleges);
					}
					boolean isAllow = AccessControlUtil.isAllow(ace);
					if (isAllow) {
						Privilege[] privs = ace.getPrivileges();
						for (int i = 0; i < privs.length; i++) {
							accessPrivleges.getGranted().add(new SerializablePrivilege(privs[i]));
						}
					} else {
						Privilege[] privs = ace.getPrivileges();
						for (int i = 0; i < privs.length; i++) {
							accessPrivleges.getDenied().add(new SerializablePrivilege(privs[i]));
						}
					}
				}
			}
			return accessMap;
		} catch (RepositoryException ex) {
			throw new InternalException("Repository exception",ex);
		}
	}

	private AccessControlEntry[] getDeclaredAccessControlEntries(Session session, String absPath) throws RepositoryException {
		AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);
		AccessControlPolicy[] policies = accessControlManager.getPolicies(absPath);
		for (AccessControlPolicy accessControlPolicy : policies) {
			if (accessControlPolicy instanceof AccessControlList) {
				AccessControlEntry[] accessControlEntries = ((AccessControlList) accessControlPolicy).getAccessControlEntries();
				return accessControlEntries;
			}
		}
		return new AccessControlEntry[0];
	}

	/** {@inheritDoc} */
	@Override
	public AccessRights getDeclaredAccessRightsForPrincipal(Node node, String principalId) throws InternalException {
		try {
			return getDeclaredAccessRightsForPrincipal(node.getSession(), node.getPath(), principalId);
		} catch (RepositoryException ex) {
			throw new InternalException("Repository exception",ex);
		}
	}

	/** {@inheritDoc} */
	@Override
	public AccessRights getDeclaredAccessRightsForPrincipal(Session session, String absPath, String principalId) throws InternalException {
		try {
			AccessRights rights = new AccessRightsImpl();
			if (principalId != null && principalId.length() > 0) {
				AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);
				AccessControlPolicy[] policies = accessControlManager.getPolicies(absPath);
				for (AccessControlPolicy accessControlPolicy : policies) {
					if (accessControlPolicy instanceof AccessControlList) {
						AccessControlEntry[] accessControlEntries = ((AccessControlList) accessControlPolicy).getAccessControlEntries();
						for (AccessControlEntry ace : accessControlEntries) {
							if (principalId.equals(ace.getPrincipal().getName())) {
								boolean isAllow = AccessControlUtil.isAllow(ace);
								if (isAllow) {
									Privilege[] privs = ace.getPrivileges();
									for (int i = 0; i < privs.length; i++) {
										rights.getGranted().add(new SerializablePrivilege(privs[i]));

									}
								} else {
									Privilege[] privs = ace.getPrivileges();
									for (int i = 0; i < privs.length; i++) {
										rights.getDenied().add(new SerializablePrivilege(privs[i]));

									}
								}
							}
						}
					}
				}
			}

			return rights;
		} catch (RepositoryException ex) {
			throw new InternalException("Repository exception: " + absPath, ex);
		} finally {
		}

	}

	/** {@inheritDoc} */
	@Override
	public Map<Principal, AccessRights> getEffectiveAccessRights(Node node) throws InternalException {
		Map<Principal, AccessRights> accessRights;
		try {
			accessRights = getEffectiveAccessRights(node.getSession(), node.getPath());
		} catch (RepositoryException ex) {
			throw new InternalException("Repository exception", ex);
		}
		return accessRights;
	}

	/** {@inheritDoc} */
	@Override
	public Map<Principal, AccessRights> getEffectiveAccessRights(Session session, String absPath) throws InternalException {
		try {
			Map<Principal, AccessRights> accessMap = new LinkedHashMap<Principal, AccessRights>();
			AccessControlEntry[] entries = getEffectiveAccessControlEntries(session, absPath);
			if (entries != null) {
				for (AccessControlEntry ace : entries) {
					Principal principal = ace.getPrincipal();
					AccessRights accessPrivleges = accessMap.get(principal);
					if (accessPrivleges == null) {
						accessPrivleges = new AccessRightsImpl();
						accessMap.put(principal, accessPrivleges);
					}
					boolean allow = AccessControlUtil.isAllow(ace);
					if (allow) {
						Privilege[] privs = ace.getPrivileges();
						for (int i = 0; i < privs.length; i++) {
							accessPrivleges.getGranted().add(new SerializablePrivilege(privs[i]));
						}
					} else {
						Privilege[] privs = ace.getPrivileges();
						for (int i = 0; i < privs.length; i++) {
							accessPrivleges.getDenied().add(new SerializablePrivilege(privs[i]));
						}
					}
				}
			}
			return accessMap;
		} catch (RepositoryException ex) {
			throw new InternalException("Repository exception: ",ex);
		}
	}

	private AccessControlEntry[] getEffectiveAccessControlEntries(Session session, String absPath) throws RepositoryException {
		AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);
		AccessControlPolicy[] policies = accessControlManager.getEffectivePolicies(absPath);
		for (AccessControlPolicy accessControlPolicy : policies) {
			if (accessControlPolicy instanceof AccessControlList) {
				AccessControlEntry[] accessControlEntries = ((AccessControlList) accessControlPolicy).getAccessControlEntries();
				return accessControlEntries;
			}
		}
		return new AccessControlEntry[0];
	}

	/** {@inheritDoc} */
	@Override
	public AccessRights getEffectiveAccessRightsForPrincipal(Node node, String principalId) throws InternalException {
		try {
			return getEffectiveAccessRightsForPrincipal(node.getSession(), node.getPath(), principalId);
		} catch (RepositoryException ex) {
			throw new InternalException("Repository exception",ex);
		}
	}

	/** {@inheritDoc} */
	@Override
	public AccessRights getEffectiveAccessRightsForPrincipal(Session session, String absPath, String principalId) throws InternalException {
		AccessRights rights = new AccessRightsImpl();
		if (principalId != null && principalId.length() > 0) {
			try {
				AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);
				AccessControlPolicy[] policies = accessControlManager.getEffectivePolicies(absPath);
				for (AccessControlPolicy accessControlPolicy : policies) {
					if (accessControlPolicy instanceof AccessControlList) {
						AccessControlEntry[] accessControlEntries = ((AccessControlList) accessControlPolicy).getAccessControlEntries();
						for (AccessControlEntry ace : accessControlEntries) {
							if (principalId.equals(ace.getPrincipal().getName())) {
								boolean isAllow = AccessControlUtil.isAllow(ace);
								if (isAllow) {
									Privilege[] privs = ace.getPrivileges();
									for (int i = 0; i < privs.length; i++) {
										rights.getGranted().add(new SerializablePrivilege(privs[i]));
									}
								} else {
									Privilege[] privs = ace.getPrivileges();
									for (int i = 0; i < privs.length; i++) {
										rights.getDenied().add(new SerializablePrivilege(privs[i]));
									}
								}
							}
						}
					}
				}
			} catch (UnsupportedRepositoryOperationException ex) {
			throw new InternalException("Unsupported Operation Repository exception",ex);
			} catch (RepositoryException ex) {
			throw new InternalException("Repository exception",ex);
			}
		}

		return rights;
	}

	/** {@inheritDoc} */
	@Override
	public boolean canAddChildren(Node node) {
		try {
			return canAddChildren(node.getSession(), node.getPath());
		} catch (RepositoryException e) {
			return false;
		}
	}

	/** {@inheritDoc} */
	@Override
	public boolean canAddChildren(Session session, String absPath) {
		try {
			AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);
			return accessControlManager.hasPrivileges(absPath, new Privilege[]{
						accessControlManager.privilegeFromName(Privilege.JCR_ADD_CHILD_NODES)
					});
		} catch (RepositoryException e) {
			return false;
		}
	}

	/** {@inheritDoc} */
	@Override
	public boolean canDeleteChildren(Node node) {
		try {
			return canDeleteChildren(node.getSession(), node.getPath());
		} catch (RepositoryException e) {
			return false;
		}
	}

	/** {@inheritDoc} */
	@Override
	public boolean canDeleteChildren(Session session, String absPath) {
		try {
			AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);

			return accessControlManager.hasPrivileges(absPath, new Privilege[]{
						accessControlManager.privilegeFromName(Privilege.JCR_REMOVE_CHILD_NODES)
					});
		} catch (RepositoryException e) {
			return false;
		}
	}

	/** {@inheritDoc} */
	@Override
	public boolean canDelete(Node node) {
		try {
			return canDelete(node.getSession(), node.getPath());
		} catch (RepositoryException e) {
			return false;
		}
	}

	/** {@inheritDoc} */
	@Override
	public boolean canDelete(Session session, String absPath) {
		try {
			AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);

			String parentPath = absPath.substring(0, absPath.lastIndexOf('/'));
			boolean canDelete = accessControlManager.hasPrivileges(absPath, new Privilege[]{
						accessControlManager.privilegeFromName(Privilege.JCR_REMOVE_NODE)
					}) && canDeleteChildren(session, parentPath);
			return canDelete;
		} catch (RepositoryException e) {
			return false;
		}
	}

	/** {@inheritDoc} */
	@Override
	public boolean canModifyProperties(Node node) {
		try {
			return canModifyProperties(node.getSession(), node.getPath());
		} catch (RepositoryException e) {
			return false;
		}
	}

	/** {@inheritDoc} */
	@Override
	public boolean canModifyProperties(Session session, String absPath) {
		try {
			AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);
			return accessControlManager.hasPrivileges(absPath, new Privilege[]{
						accessControlManager.privilegeFromName(Privilege.JCR_MODIFY_PROPERTIES)
					});
		} catch (RepositoryException e) {
			return false;
		}
	}

	/** {@inheritDoc} */
	@Override
	public boolean canReadAccessControl(Node node) {
		try {
			return canReadAccessControl(node.getSession(), node.getPath());
		} catch (RepositoryException e) {
			return false;
		}
	}

	/** {@inheritDoc} */
	@Override
	public boolean canReadAccessControl(Session session, String absPath) {
		try {
			AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);
			return accessControlManager.hasPrivileges(absPath, new Privilege[]{
						accessControlManager.privilegeFromName(Privilege.JCR_READ_ACCESS_CONTROL)
					});
		} catch (RepositoryException e) {
			return false;
		}
	}

	/** {@inheritDoc} */
	@Override
	public boolean canModifyAccessControl(Node node) {
		try {
			return canModifyAccessControl(node.getSession(), node.getPath());
		} catch (RepositoryException e) {
			return false;
		}
	}

	/** {@inheritDoc} */
	@Override
	public boolean canModifyAccessControl(Session session, String absPath) {
		try {
			AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);
			return accessControlManager.hasPrivileges(absPath, new Privilege[]{
						accessControlManager.privilegeFromName(Privilege.JCR_MODIFY_ACCESS_CONTROL)
					});
		} catch (RepositoryException e) {
			return false;
		}
	}

	/** {@inheritDoc} */
	@Override
	public boolean canUpdateAuthorizable(Session session, String principalID) {
		try {
			PrincipalManager principalManager = AccessControlUtil.getPrincipalManager(session);
			Principal principal = principalManager.getPrincipal(principalID);
			if (principal == null) {
				return false;
			}

			String path = getAuthorizableItemPath(principal);
			return canModifyProperties(session, path);
		} catch (Exception e) {
			//just eat it.
			return false;
		}
	}

	/** {@inheritDoc} */
	private String getAuthorizableItemPath(Principal principal)
			throws NoSuchMethodException, IllegalAccessException,
			InvocationTargetException {
		//should check if principal implements ItemBasedPrincipal, but it is not visible here so use reflection instead
		Method method = principal.getClass().getMethod("getPath");
		String path = (String) method.invoke(principal);
		return path;
	}

	/** {@inheritDoc} */
	@Override
	public boolean canDeleteAuthorizable(Session session, String principalID) {
		try {
			PrincipalManager principalManager = AccessControlUtil.getPrincipalManager(session);
			Principal principal = principalManager.getPrincipal(principalID);
			if (principal == null) {
				return false;
			}

			//should check if principal implements ItemBasedPrincipal, but it is not visible here so use reflection instead
			String path = getAuthorizableItemPath(principal);
			return canDelete(session, path);
		} catch (Exception e) {
			//just eat it.
			return false;
		}
	}

	/** {@inheritDoc} */
	@Override
	public void setAclByName(Session session, String principalName, String path, AccessRights privileges) throws InternalException, PrincipalNotExistsException {
		try {
			UserManager userManager = AccessControlUtil.getUserManager(session);
			//Authorizable authorizable = null;
			Principal principal = null;
			if (!principalName.equalsIgnoreCase("everyone")) {
				principal = userManager.getAuthorizable(principalName).getPrincipal();
				if (principal == null) {
					throw new PrincipalNotExistsException("Principal does not exists: " + principalName);
				}
			} else {
				principal = EveryonePrincipal.getInstance();
			}

			AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);

			// Get or create the ACL for the node.
			AccessControlList acl = null;
			AccessControlPolicy[] policies = accessControlManager.getPolicies(path);
			for (AccessControlPolicy policy : policies) {
				if (policy instanceof AccessControlList) {
					acl = (AccessControlList) policy;
					break;
				}
			}
			
			if (acl == null) {
				AccessControlPolicyIterator applicablePolicies = accessControlManager.getApplicablePolicies(path);
				while (applicablePolicies.hasNext()) {
					AccessControlPolicy policy = applicablePolicies.nextAccessControlPolicy();
					if (policy instanceof AccessControlList) {
						acl = (AccessControlList) policy;
						break;
					}
				}
			}
			
			if (acl == null) {
				throw new RepositoryException("Could not obtain ACL for resource " + path);
			}
			
			// Combine all existing ACEs for the target principal.
			AccessControlEntry[] accessControlEntries = acl.getAccessControlEntries();
			for (int i=0; i < accessControlEntries.length; i++) {
	    		AccessControlEntry ace = accessControlEntries[i];
	    		if (principal.equals(ace.getPrincipal())) {
	    			// First remove old ACE for user
	    			acl.removeAccessControlEntry(ace);
	    		}
				break;
			}
			
			// Set new ACL
			if (privileges.getGranted() != null && privileges.getGranted().size()>0) {
				SerializablePrivilege[] granted = new SerializablePrivilege[privileges.getGranted().size()];
				System.arraycopy(privileges.getGranted().toArray(), 0, granted, 0, privileges.getGranted().size());
				if (!AccessControlUtil.addEntry(acl, principal, PrivilegeFromSerializable.fromSerializableArray(accessControlManager, granted), true)) {
					throw new RepositoryException("Could not set granted rights for principal: " + principal);
				}
			}

			if (privileges.getDenied() != null && privileges.getDenied().size()>0) {
				SerializablePrivilege[] denied = new SerializablePrivilege[privileges.getDenied().size()];
				System.arraycopy(privileges.getDenied().toArray(), 0, denied, 0, privileges.getDenied().size());
				if (!AccessControlUtil.addEntry(acl, principal, PrivilegeFromSerializable.fromSerializableArray(accessControlManager, denied), false)) {
					throw new RepositoryException("Could not set granted denied for principal: " + principal);
				}
			}
			accessControlManager.setPolicy(path, acl);

		} catch (RepositoryException ex) {
			throw new InternalException("Repository exception", ex);
		} finally {
		}

	}

	/** {@inheritDoc} */
	@Override
	public AccessRights getAclByName(Session session, String principalId, String absPath) throws InternalException {
		AccessRights rights = new AccessRightsImpl();

		try {
			if (principalId != null && principalId.length() > 0) {
				AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);
				AccessControlPolicy[] policies = accessControlManager.getPolicies(absPath);
				for (AccessControlPolicy accessControlPolicy : policies) {
					if (accessControlPolicy instanceof AccessControlList) {
						AccessControlEntry[] accessControlEntries = ((AccessControlList) accessControlPolicy).getAccessControlEntries();
						for (AccessControlEntry ace : accessControlEntries) {
							if (principalId.equals(ace.getPrincipal().getName())) {
								boolean isAllow = AccessControlUtil.isAllow(ace);
								if (isAllow) {
									Privilege[] privs = ace.getPrivileges();
									for (int i = 0; i < privs.length; i++) {
										rights.getGranted().add(new SerializablePrivilege(privs[i]));

									}
								} else {
									Privilege[] privs = ace.getPrivileges();
									for (int i = 0; i < privs.length; i++) {
										rights.getDenied().add(new SerializablePrivilege(privs[i]));

									}
								}
							}
						}
					}
				}
			}
		} catch (RepositoryException ex) {
			throw new InternalException("Repository exception", ex);
		} finally {
		}

		return rights;
	}
}

