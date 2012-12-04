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

/**
 *
 * @author Robert Csakany (robson@semmi.se)
 * @created Feb 13, 2010
 */
import java.util.ArrayList;
import java.util.Dictionary;
import java.util.Hashtable;

import javax.jcr.Repository;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.observation.Event;
import javax.jcr.observation.EventIterator;
import javax.jcr.observation.EventListener;
import javax.jcr.observation.ObservationManager;

import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.ReferencePolicy;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.event.jobs.JobUtil;
import org.apache.sling.jcr.api.SlingRepository;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.event.EventAdmin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Observe the users  for changes, and create a
 * user generation job when user are added/deleted.
 */
/*@Component(
		label = "%userResourceChangeListener.name", 
		description = "%userResourceChangeListener.description", 
		immediate = true, 
		metatype = false
)*/
public class UserResourceChangeListener {
	private static final Logger log = LoggerFactory.getLogger(UserResourceChangeListener.class);

	public static final String USER_GENERATE_TOPIC = "org/liveSense/user/generate";
	public static final String USER_REMOVE_TOPIC = "org/liveSense/user/remove";

	@Reference(cardinality=ReferenceCardinality.MANDATORY_UNARY, policy=ReferencePolicy.DYNAMIC)
	private SlingRepository repository;
	@Reference(cardinality=ReferenceCardinality.MANDATORY_UNARY, policy=ReferencePolicy.DYNAMIC)
	private EventAdmin eventAdmin;
	@Reference(cardinality=ReferenceCardinality.MANDATORY_UNARY, policy=ReferencePolicy.DYNAMIC)
	ResourceResolverFactory resourceResolverFactory;

	Session session;

	class PathEventListener implements EventListener {

		private void generateJobEvent(String userName) {
			log.info("> Create user create event " + JobUtil.PROPERTY_JOB_TOPIC + " " + USER_GENERATE_TOPIC + " for " + userName);
			final Dictionary<String, Object> props = new Hashtable<String, Object>();
			props.put(JobUtil.PROPERTY_JOB_TOPIC, USER_GENERATE_TOPIC);
			props.put("userName", userName);
			org.osgi.service.event.Event createUserJob = new org.osgi.service.event.Event(JobUtil.TOPIC_JOB, props);
			eventAdmin.sendEvent(createUserJob);
		}

		private void removeJobEvent(String userName) {
			log.info("> Create user remove event " + JobUtil.PROPERTY_JOB_TOPIC + " " + USER_REMOVE_TOPIC + " for "  + userName);
			final Dictionary<String, Object> props = new Hashtable<String, Object>();
			props.put(JobUtil.PROPERTY_JOB_TOPIC, USER_REMOVE_TOPIC);
			props.put("userName", userName);
			org.osgi.service.event.Event removeUserJob = new org.osgi.service.event.Event(JobUtil.TOPIC_JOB, props);
			eventAdmin.sendEvent(removeUserJob);
		}

		@Override
		public void onEvent(EventIterator it) {
			while (it.hasNext()) {
				Event event = it.nextEvent();
				/*
				2012-02-08_12:04:37.314 INFO  logs/request.log - 08/Feb/2012:12:04:37 +0100 [9] -> POST /system/userManager/user.create.json HTTP/1.1
				2012-02-08_12:04:37.327 INFO  o.l.s.s.UserResourceChangeListener - userChanged: 4 /rep:security/rep:authorizables/rep:users/t/te/test001/jcr:primaryType
				2012-02-08_12:04:37.327 INFO  o.l.s.s.UserResourceChangeListener - userChanged: 4 /rep:security/rep:authorizables/rep:users/t/te/test001/jcr:uuid
				2012-02-08_12:04:37.328 INFO  o.l.s.s.UserResourceChangeListener - userChanged: 4 /rep:security/rep:authorizables/rep:users/t/te/test001/rep:password
				2012-02-08_12:04:37.328 INFO  o.l.s.s.UserResourceChangeListener - userChanged: 4 /rep:security/rep:authorizables/rep:users/t/te/test001/jcr:created
				2012-02-08_12:04:37.328 INFO  logs/request.log - 08/Feb/2012:12:04:37 +0100 [9] <- 200 application/json 14ms
				2012-02-08_12:04:37.328 INFO  o.l.s.s.UserResourceChangeListener - userChanged: 4 /rep:security/rep:authorizables/rep:users/t/te/test001/rep:principalName
				2012-02-08_12:04:37.328 INFO  logs/access.log - 127.0.0.1 - admin 08/Feb/2012:12:04:37 +0100 "POST /system/userManager/user.create.json HTTP/1.1" 200 397 "http://localhost:8080/system/userManager/user.create.html" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.7 Safari/535.19"
				2012-02-08_12:04:37.329 INFO  o.l.s.s.UserResourceChangeListener - userChanged: 4 /rep:security/rep:authorizables/rep:users/t/te/test001/jcr:createdBy
				
				In user operations only the propery change is catched as event. We cannot determinate the Node operations.
				*/
				
				
				// TODO Determinate user deletation
				try {

//					String eventType = (event.getType() == Event.NODE_ADDED ? "NODE_ADDED" : (event.getType() == Event.NODE_REMOVED ? "NODE_REMOVED" : "NODE_REMOVED"));
					log.info("userChanged: "+event.getType()+" "+event.getPath());
					String pathParts[] = event.getPath().split("/");

					// It's not cathed yet
					if (event.getType() == Event.NODE_ADDED) {
						generateJobEvent(pathParts[pathParts.length-1]);
					} else if (event.getType() == Event.NODE_REMOVED) {
						removeJobEvent(pathParts[pathParts.length-1]);
					}
					
					// If jcr:primaryType property added, new user added
					if (event.getType() == Event.PROPERTY_ADDED && event.getPath().endsWith("/jcr:primaryType")) {
						generateJobEvent(pathParts[pathParts.length-2]);						
					}
					
				} catch (Exception e) {
					log.error(e.getMessage(), e);
				}
			}
		}
	}

	private final ArrayList<PathEventListener> eventListeners = new ArrayList<PathEventListener>();

	private ObservationManager observationManager;

	/**
	 * Activates this component.
	 *
	 * @param componentContext The OSGi <code>ComponentContext</code> of this
	 *            component.
	 */
	protected void activate(ComponentContext componentContext) throws RepositoryException {

		session = repository.loginAdministrative("security");
		if (repository.getDescriptor(Repository.OPTION_OBSERVATION_SUPPORTED).equals("true")) {
			observationManager = session.getWorkspace().getObservationManager();
			String[] nodeType = {"rep:User"};

			PathEventListener listener = new PathEventListener();
			eventListeners.add(listener);
			observationManager.addEventListener(listener, Event.NODE_REMOVED | Event.NODE_REMOVED | Event.PROPERTY_ADDED | Event.PROPERTY_CHANGED | Event.PROPERTY_REMOVED | Event.NODE_MOVED, "/rep:security/rep:authorizables/", true, null, nodeType, true);
		}
	}

	public void deactivate(ComponentContext componentContext) throws RepositoryException {
		if (observationManager != null) {
			for (PathEventListener listener : eventListeners) {
				observationManager.removeEventListener(listener);
			}
		}
		if (session != null && session.isLive())
			session.logout();
	}
}
