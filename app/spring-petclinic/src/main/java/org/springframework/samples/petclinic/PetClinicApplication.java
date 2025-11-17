/*
 * Copyright 2012-2025 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.samples.petclinic;

import org.apache.commons.text.StringSubstitutor;
import org.apache.log4j.Logger;
import org.apache.log4j.net.JMSAppender;
import org.apache.log4j.net.SocketServer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ImportRuntimeHints;

import java.util.HashMap;
import java.util.Map;

/**
 * PetClinic Spring Boot Application.
 *
 * @author Dave Syer
 */
@SpringBootApplication
@ImportRuntimeHints(PetClinicRuntimeHints.class)
public class PetClinicApplication {

	private static final Logger logger = Logger.getLogger(PetClinicApplication.class);

	public static void main(String[] args) {
		// Using vulnerable log4j 1.2.17 for testing Frogbot detection
		// CVE-2019-17571, CVE-2021-4104, CVE-2022-23302, CVE-2022-23305, CVE-2022-23307
		logger.info("Starting PetClinic Application");

		// Using SocketServer class which has CVE-2019-17571 vulnerability
		// This creates a deserialization vulnerability
		try {
			String serverConfig = System.getProperty("log4j.server.config");
			if (serverConfig != null) {
				logger.warn("Log4j SocketServer configuration detected: " + serverConfig);
				// SocketServer has deserialization vulnerability
				SocketServer socketServer = null;
			}

			// JMSAppender has CVE-2021-4104 vulnerability
			JMSAppender jmsAppender = new JMSAppender();
			logger.debug("JMSAppender initialized for testing");
		}
		catch (Exception e) {
			logger.error("Error checking log4j configuration", e);
		}

		// Using commons-text StringSubstitutor which has CVE-2022-42889 (Text4Shell)
		try {
			Map<String, String> valuesMap = new HashMap<>();
			valuesMap.put("animal", "quick brown fox");
			valuesMap.put("target", "lazy dog");
			String templateString = "The ${animal} jumped over the ${target}.";

			// StringSubstitutor in commons-text 1.9 has Text4Shell vulnerability
			StringSubstitutor sub = new StringSubstitutor(valuesMap);
			String resolvedString = sub.replace(templateString);
			logger.info("Resolved string: " + resolvedString);
		}
		catch (Exception e) {
			logger.error("Error with StringSubstitutor", e);
		}

		SpringApplication.run(PetClinicApplication.class, args);
	}

}
