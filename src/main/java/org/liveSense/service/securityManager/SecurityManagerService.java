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

import java.security.Principal;
import java.util.List;
import java.util.Map;
import javax.jcr.Node;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.security.Privilege;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.sling.jcr.api.SlingRepository;
import org.liveSense.service.securityManager.exceptions.GroupAlreadyExistsException;
import org.liveSense.service.securityManager.exceptions.GroupNotExistsException;
import org.liveSense.service.securityManager.exceptions.InternalException;
import org.liveSense.service.securityManager.exceptions.PrincipalIsNotGroupException;
import org.liveSense.service.securityManager.exceptions.PrincipalIsNotUserException;
import org.liveSense.service.securityManager.exceptions.PrincipalNotExistsException;
import org.liveSense.service.securityManager.exceptions.UserAlreadyExistsException;
import org.liveSense.service.securityManager.exceptions.UserNotExistsException;
import org.liveSense.core.wrapper.GenericValue;

/**
 *
 * @author robson
 */
public interface SecurityManagerService {

	/**
	 * Add new group with the given name
	 *
	 * @param Name of group
	 * @param The peoperties added to user (Converted to Value) - Multiple values is enabled
	 * @return The created Group object
	 * @throws GroupAlreadyExistsException
	 * @throws InternalException
	 */
	Group addGroup(Session session, final String groupName, Map<String, Object> properties) throws GroupAlreadyExistsException, InternalException;

	/**
	 * Add a new user with the given name and password
	 *
	 * @param The JCR session of the current user
	 * @param The name of the user
	 * @param The password
	 * @param The properties added to user. (Converted to Value) - Multiple values is enabled
	 * @return The created user object
	 * @throws UserAlreadyExistsException
	 * @throws InternalException
	 */
	User addUser(Session session, String userName, String password, Map<String, Object> properties) throws UserAlreadyExistsException, InternalException;

	/**
	 * Checks whether the current user has been granted privileges
	 * to add children to the specified node.
	 *
	 * @param The node to check
	 * @return True if the current user has the privileges, false otherwise
	 */
	boolean canAddChildren(Node node);

	/**
	 * Checks whether the current user has been granted privileges
	 * to add children to the specified path.
	 *
	 * @param The JCR session of the current user
	 * @param The path of the resource to check
	 * @return True if the current user has the privileges, false otherwise
	 */
	boolean canAddChildren(Session session, String absPath);

	/**
	 * Checks whether the current user has been granted privileges
	 * to delete the specified node.
	 *
	 * @param The node to check
	 * @return True if the current user has the privileges, false otherwise
	 */
	boolean canDelete(Node node);

	/**
	 * Checks whether the current user has been granted privileges
	 * to delete the specified path.
	 *
	 * @param The JCR session of the current user
	 * @param The path of the resource to check
	 * @return True if the current user has the privileges, false otherwise
	 */
	boolean canDelete(Session session, String absPath);

	/**
	 * Checks whether the current user has been granted privileges
	 * to delete the specified principal.
	 *
	 * @param The JCR session of the current user
	 * @param The id of the principal to check
	 * @return True if the current user has the privileges, false otherwise
	 */
	boolean canDeleteAuthorizable(Session session, String principalID);

	/**
	 * Checks whether the current user has been granted privileges
	 * to delete children to the specified node
	 *
	 * @param The JCR session of the current user
	 * @param The node to check
	 * @return True if the current user has the privileges, false otherwise
	 */
	boolean canDeleteChildren(Node node);

	/**
	 * Checks whether the current user has been granted privileges
	 * to delete children of the specified path.
	 *
	 * @param The JCR session of the current user
	 * @param The path of the resource to check
	 * @return True if the current user has the privileges, false otherwise
	 */
	boolean canDeleteChildren(Session session, String absPath);

	/**
	 * Checks whether the current user has been granted privileges
	 * to modify the access control of the specified node.
	 *
	 * @param The node to check
	 * @return True if the current user has the privileges, false otherwise
	 */
	boolean canModifyAccessControl(Node node);

	/**
	 * Checks whether the current user has been granted privileges
	 * to modify the access control of the specified path.
	 *
	 * @param The JCR session of the current user
	 * @param The path of the resource to check
	 * @return True if the current user has the privileges, false otherwise
	 */
	boolean canModifyAccessControl(Session session, String absPath);

	/**
	 * Checks whether the current user has been granted privileges
	 * to modify properties of the specified node.
	 *
	 * @param The node to check
	 * @return True if the current user has the privileges, false otherwise
	 */
	boolean canModifyProperties(Node node);

	/**
	 * Checks whether the current user has been granted privileges
	 * to modify properties of the specified path.
	 *
	 * @param The JCR session of the current user
	 * @param The path of the resource to check
	 * @return true if the current user has the privileges, false otherwise
	 */
	boolean canModifyProperties(Session session, String absPath);

	/**
	 * Checks whether the current user has been granted privileges
	 * to read the access control of the specified node.
	 *
	 * @param The node to check
	 * @return True if the current user has the privileges, false otherwise
	 */
	boolean canReadAccessControl(Node node);

	/**
	 * Checks whether the current user has been granted privileges
	 * to read the access control of the specified path.
	 *
	 * @param The JCR session of the current user
	 * @param The path of the resource to check
	 * @return True if the current user has the privileges, false otherwise
	 */
	boolean canReadAccessControl(Session session, String absPath);

	/**
	 * Checks whether the current user has been granted privileges
	 * to update the properties of the specified principal.
	 *
	 * @param The JCR session of the current user
	 * @param The id of the principal to check
	 * @return True if the current user has the privileges, false otherwise
	 */
	boolean canUpdateAuthorizable(Session session, String principalID);

	/**
	 * Change the password of the user
	 *
	 * @param The JCR session of the current user
	 * @param Name of the user
	 * @param Password
	 * @throws UserNotExistsException
	 * @throws PrincipalIsNotUserException
	 * @throws InternalException
	 */
	void changePasswordByName(Session session, String userName, String password) throws UserNotExistsException, PrincipalIsNotUserException, InternalException;

	/**
	 * Delete group with the given name
	 *
	 * @param The JCR session of the current user
	 * @param The name of the group
	 * @throws GroupNotExistsException
	 * @throws InternalException
	 * @throws PrincipalIsNotGroupException
	 */
	void deleteGroupByName(Session session, String groupName) throws GroupNotExistsException, InternalException, PrincipalIsNotGroupException;

	/**
	 * Delete the user with the given name
	 *
	 * @param The JCR session of the current user
	 * @param The name of the user
	 * @throws UserNotExistsException
	 * @throws InternalException
	 * @throws PrincipalIsNotUserException
	 */
	void deleteUserByName(Session session, String userName) throws UserNotExistsException, InternalException, PrincipalIsNotUserException;


	/**
	 * Get the access rights of the given principal
	 *
	 * @param The JCR session of the current user
	 * @param The Principal name (Group or User)
	 * @param JCR Path
	 * @return
	 * @throws InternalException
	 */
	AccessRights getAclByName(Session session, String principalId, String absPath) throws InternalException;

	/**
	 * Get JCR Authorizable object
	 *
	 * @param The JCR session of the current user
	 * @param The Principal name (Group or User)
	 * @return The Authorizable
	 * @throws PrincipalNotExistsException
	 * @throws InternalException
	 */
	Authorizable getAuthorizableByName(Session session, String principal) throws PrincipalNotExistsException, InternalException;

	/**
	 * Returns the mapping of declared access rights that have been set for the resource at
	 * the given path.
	 *
	 * @param The node to get the access rights for
	 * @return Map of access rights.  Key is the user/group principal, value contains the granted/denied privileges
	 * @throws InternalException
	 */
	Map<Principal, AccessRights> getDeclaredAccessRights(Node node) throws InternalException;

	/**
	 * Returns the mapping of declared access rights that have been set for the resource at
	 * the given path.
	 *
	 * @param The JCR session of the current user
	 * @param The path of the resource to get the access rights for
	 * @return Map of access rights.  Key is the user/group principal, value contains the granted/denied privileges
	 * @throws InternalException
	 */
	Map<Principal, AccessRights> getDeclaredAccessRights(Session session, String absPath) throws InternalException;

	/**
	 * Returns the declared access rights for the specified Node for the given
	 * principalId.
	 *
	 * @param The JCR node to retrieve the access rights for
	 * @param The principalId to get the access rights for
	 * @return access rights for the specified principal
	 * @throws InternalException
	 */
	AccessRights getDeclaredAccessRightsForPrincipal(Node node, String principalId) throws InternalException;

	/**
	 * Returns the declared access rights for the resource at the specified path for the given
	 * principalId.
	 *
	 * @param The path of the resource to retrieve the rights for
	 * @param The principalId to get the access rights for
	 * @return Access rights for the specified principal
	 * @throws InternalException
	 */
	AccessRights getDeclaredAccessRightsForPrincipal(Session session, String absPath, String principalId) throws InternalException;

	/**
	 * Get the declared list of groups where the given principal is member
	 *
	 * @param The JCR session of the current user
	 * @param The name of the Principal
	 * @return The aggregated list of group
	 * @throws PrincipalNotExistsException
	 * @throws InternalException
	 */
	List<Group> getDeclaredMemberOfByName(Session session, String principal) throws PrincipalNotExistsException, InternalException;

	/**
	 * Get the given group's effective list of members
	 *
	 * @param The JCR session of the current user
	 * @param Name of group
	 * @return The list of Authorizables
	 * @throws InternalException
	 * @throws PrincipalIsNotGroupException
	 * @throws GroupNotExistsException
	 */
	List<Authorizable> getDeclaredMembersByName(Session session, String groupName) throws InternalException, PrincipalIsNotGroupException, GroupNotExistsException;

	/**
	 * Returns the mapping of effective access rights that have been set for the resource at
	 * the given path.
	 *
	 * @param The node to get the access rights for
	 * @return Map of access rights.  Key is the user/group principal, value contains the granted/denied privileges
	 * @throws InternalException
	 */
	Map<Principal, AccessRights> getEffectiveAccessRights(Node node) throws InternalException;

	/**
	 * Returns the mapping of effective access rights that have been set for the resource at
	 * the given path.
	 *
	 * @param The JCR session of the current user
	 * @param The path of the resource to get the access rights for
	 * @return Map of access rights.  Key is the user/group principal, value contains the granted/denied privileges
	 * @throws InternalException
	 */
	Map<Principal, AccessRights> getEffectiveAccessRights(Session session, String absPath) throws InternalException;

	/**
	 * Returns the effective access rights for the specified Node for the given
	 * principalId.
	 *
	 * @param The JCR node to retrieve the access rights for
	 * @param The principalId to get the access rights for
	 * @return Access rights for the specified principal
	 * @throws InternalException
	 */
	AccessRights getEffectiveAccessRightsForPrincipal(Node node, String principalId) throws InternalException;

	/**
	 * Returns the effective access rights for the resource at the specified path for the given
	 * principalId.
	 *
	 * @param The JCR session of the current user
	 * @param The path of the resource to retrieve the rights for
	 * @param The principalId to get the access rights for
	 * @return Access rights for the specified principal
	 * @throws InternalException
	 */
	AccessRights getEffectiveAccessRightsForPrincipal(Session session, String absPath, String principalId) throws InternalException;

	/**
	 * Get the aggragate list of groups where the given principal is member
	 *
	 * @param The JCR session of the current user
	 * @param The name of Principal
	 * @return The aggregated list of group
	 * @throws PrincipalNotExistsException
	 * @throws InternalException
	 */
	List<Group> getEffectiveMemberOfByName(Session session, String principal) throws PrincipalNotExistsException, InternalException;

	/**
	 * Get the given group's aggragate list of members
	 *
	 * @param The JCR session of the current user
	 * @param Name of group
	 * @return The list of Authorizables
	 * @throws InternalException
	 * @throws PrincipalIsNotGroupException
	 * @throws GroupNotExistsException
	 */
	List<Authorizable> getEffectiveMembersByName(Session session, String groupName) throws InternalException, PrincipalIsNotGroupException, GroupNotExistsException;

	/**
	 * Get Group by group name
	 *
	 * @param The JCR session of the current user
	 * @param The name of group
	 * @return The Group
	 * @throws GroupNotExistsException
	 * @throws InternalException
	 * @throws PrincipalIsNotGroupException
	 */
	Group getGroupByName(Session session, String groupName) throws GroupNotExistsException, InternalException, PrincipalIsNotGroupException;

	/**
	 * Get the properties of the given principal
	 *
	 * @param The JCR session of the current user
	 * @param The name of Pricipal
	 * @return The map of setted properties of authorizable
	 * @throws GroupNotExistsException
	 * @throws InternalException\
	 * @throws PrincipalIsNotGroupException
	 */
	Map<String, GenericValue> getPrincipalPropertiesByName(Session session, String principal) throws PrincipalNotExistsException, InternalException;

	/**
	 * Returns the JCR repository used by this service.
	 */
	SlingRepository getRepository() throws RepositoryException;

	/**
	 * Return the supported Privileges for the specified node.
	 *
	 * @param The node to check
	 * @return Array of Privileges
	 * @throws InternalException
	 */
	SerializablePrivilege[] getSupportedPrivileges(Node node) throws InternalException;

	/**
	 * Returns the supported privileges for the specified path.
	 *
	 * @param The JCR session of the current user
	 * @param The path to get the privileges for
	 * @return Array of Privileges
	 * @throws InternalException
	 */
	SerializablePrivilege[] getSupportedPrivileges(Session session, String absPath) throws InternalException;

	/**
	 * Get User by Name
	 *
	 * @param The JCR session of the current user
	 * @param The name of the user
	 * @return The User
	 * @throws UserNotExistsException
	 * @throws InternalException
	 * @throws PrincipalIsNotUserException
	 */
	User getUserByName(Session session, String userName) throws UserNotExistsException, InternalException, PrincipalIsNotUserException;

	/**
	 * Modify the properties of the given principal
	 *
	 * @param The JCR session of the current user
	 * @param Tha name of user
	 * @param Password
	 * @param Properties
	 * @throws UserNotExistsException
	 * @throws InternalException
	 * @throws PrincipalIsNotUserException
	 */
	void modifyPrincipalPropertiesByName(Session session, String principal, Map<String, GenericValue> properties) throws UserNotExistsException, InternalException, PrincipalIsNotUserException;


	/**
	 * Set the ACL for the given principal
	 *
	 * @param The JCR session of the current user
	 * @param Principal
	 * @param Path
	 * @param Privileges
	 * @throws InternalException
	 * @throws PrincipalNotExistsException
	 */
	void setAclByName(Session session, String principal, String path, AccessRights privileges) throws InternalException, PrincipalNotExistsException;

}
