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

package org.liveSense.service.securityManager.gwt;

import com.google.gwt.user.client.rpc.RemoteService;
import java.security.Principal;
import java.util.List;
import java.util.Map;
import org.liveSense.service.securityManager.AccessRights;
import org.liveSense.service.securityManager.SerializablePrivilege;
import org.liveSense.service.securityManager.exceptions.AccessDeniedException;
import org.liveSense.service.securityManager.exceptions.GroupAlreadyExistsException;
import org.liveSense.service.securityManager.exceptions.GroupNotExistsException;
import org.liveSense.service.securityManager.exceptions.InternalException;
import org.liveSense.service.securityManager.exceptions.PrincipalIsNotGroupException;
import org.liveSense.service.securityManager.exceptions.PrincipalIsNotUserException;
import org.liveSense.service.securityManager.exceptions.PrincipalNotExistsException;
import org.liveSense.service.securityManager.exceptions.UserAlreadyExistsException;
import org.liveSense.service.securityManager.exceptions.UserNotExistsException;
import org.liveSense.utils.GenericValue;

/**
 *
 * @author robson
 */
public interface SecurityManagerServiceRemoteAsync {

	void addGroup(String groupName, Map<String, Object> properties) throws GroupAlreadyExistsException, InternalException, AccessDeniedException;

	void addUser(String userName, String password, Map<String, Object> properties) throws UserAlreadyExistsException, InternalException, AccessDeniedException;

	boolean canAddChildren(String absPath) throws AccessDeniedException, InternalException;

	boolean canDelete(String absPath) throws AccessDeniedException, InternalException;

	boolean canDeleteAuthorizable(String principalID) throws AccessDeniedException, InternalException;

	boolean canDeleteChildren(String absPath) throws AccessDeniedException, InternalException;

	boolean canModifyAccessControl(String absPath) throws AccessDeniedException, InternalException;

	boolean canModifyProperties(String absPath) throws AccessDeniedException, InternalException;

	boolean canReadAccessControl(String absPath) throws AccessDeniedException, InternalException;

	boolean canUpdateAuthorizable(String principalID) throws AccessDeniedException, InternalException;

	void changePasswordByName(String userName, String password) throws UserNotExistsException, PrincipalIsNotUserException, InternalException, AccessDeniedException;

	void deleteGroupByName(String groupName) throws GroupNotExistsException, InternalException, PrincipalIsNotGroupException, AccessDeniedException;

	void deleteUserByName(String userName) throws UserNotExistsException, InternalException, PrincipalIsNotUserException, AccessDeniedException;

	AccessRights getAclByName(String principalId, String absPath) throws InternalException, AccessDeniedException;

	Map<Principal, AccessRights> getDeclaredAccessRights(String absPath) throws InternalException, AccessDeniedException;

	AccessRights getDeclaredAccessRightsForPrincipal(String absPath, String principalId) throws InternalException, AccessDeniedException;

	List<String> getDeclaredMemberOfByName(String principal) throws PrincipalNotExistsException, InternalException, AccessDeniedException;

	List<String> getDeclaredMembersByName(String groupName) throws InternalException, PrincipalIsNotGroupException, GroupNotExistsException, AccessDeniedException;

	Map<Principal, AccessRights> getEffectiveAccessRights(String absPath) throws InternalException, AccessDeniedException;

	AccessRights getEffectiveAccessRightsForPrincipal(String absPath, String principalId) throws InternalException, AccessDeniedException;

	List<String> getEffectiveMemberOfByName(String principal) throws PrincipalNotExistsException, InternalException, AccessDeniedException;

	List<String> getEffectiveMembersByName(String groupName) throws InternalException, PrincipalIsNotGroupException, GroupNotExistsException, AccessDeniedException;

	Map<String, GenericValue> getPrincipalPropertiesByName(String principal) throws PrincipalNotExistsException, InternalException, AccessDeniedException;

	SerializablePrivilege[] getSupportedPrivileges(String absPath) throws InternalException, AccessDeniedException;

	SerializablePrivilege[] getSupportedPrivilegesAdmin(String absPath) throws InternalException, AccessDeniedException;

	void modifyPrincipalPropertiesByName(String principal, Map<String, GenericValue> properties) throws UserNotExistsException, InternalException, PrincipalIsNotUserException, AccessDeniedException;

	void setAclByName(String principal, String path, AccessRights privileges) throws InternalException, PrincipalNotExistsException, AccessDeniedException;

}
