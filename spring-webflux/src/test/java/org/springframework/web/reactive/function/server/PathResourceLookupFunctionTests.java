/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.web.reactive.function.server;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.function.Function;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpMethod;
import org.springframework.web.testfixture.http.server.reactive.MockServerHttpRequest;
import org.springframework.web.testfixture.server.MockServerWebExchange;

/**
 * @author Arjen Poutsma
 */
public class PathResourceLookupFunctionTests {

	@Test
	public void normal() throws Exception {
		ClassPathResource location = new ClassPathResource("org/springframework/web/reactive/function/server/");

		PathResourceLookupFunction
				function = new PathResourceLookupFunction("/resources/**", location);
		MockServerHttpRequest mockRequest = MockServerHttpRequest.get("https://localhost/resources/response.txt").build();
		ServerRequest request = new DefaultServerRequest(MockServerWebExchange.from(mockRequest), Collections.emptyList());
		Mono<Resource> result = function.apply(request);

		File expected = new ClassPathResource("response.txt", getClass()).getFile();
		StepVerifier.create(result)
				.expectNextMatches(resource -> {
					try {
						return expected.equals(resource.getFile());
					}
					catch (IOException ex) {
						return false;
					}
				})
				.expectComplete()
				.verify();
	}

	@Test
	public void subPath() throws Exception {
		ClassPathResource location = new ClassPathResource("org/springframework/web/reactive/function/server/");

		PathResourceLookupFunction function = new PathResourceLookupFunction("/resources/**", location);
		MockServerHttpRequest mockRequest = MockServerHttpRequest.get("https://localhost/resources/child/response.txt").build();
		ServerRequest request = new DefaultServerRequest(MockServerWebExchange.from(mockRequest), Collections.emptyList());
		Mono<Resource> result = function.apply(request);
		String path = "org/springframework/web/reactive/function/server/child/response.txt";
		File expected = new ClassPathResource(path).getFile();
		StepVerifier.create(result)
				.expectNextMatches(resource -> {
					try {
						return expected.equals(resource.getFile());
					}
					catch (IOException ex) {
						return false;
					}
				})
				.expectComplete()
				.verify();
	}

	@Test
	public void notFound() throws Exception {
		ClassPathResource location = new ClassPathResource("org/springframework/web/reactive/function/server/");

		PathResourceLookupFunction function = new PathResourceLookupFunction("/resources/**", location);
		MockServerHttpRequest mockRequest = MockServerHttpRequest.get("https://example.com").build();
		ServerRequest request = new DefaultServerRequest(MockServerWebExchange.from(mockRequest), Collections.emptyList());
		Mono<Resource> result = function.apply(request);
		StepVerifier.create(result)
				.expectComplete()
				.verify();
	}

	@Test  // CVE-2024-38819
	public void rejectsEncodedPathTraversal(@TempDir Path temporaryFolder) throws Exception {
		Files.write(temporaryFolder.resolve("secret.txt"), "secret".getBytes(StandardCharsets.UTF_8));
		Path locationFolder = Files.createDirectory(temporaryFolder.resolve("public"));
		Files.write(locationFolder.resolve("response.txt"), "public".getBytes(StandardCharsets.UTF_8));

		PathResourceLookupFunction function = new PathResourceLookupFunction("/resources/**",
				new FileSystemResource(locationFolder.toString() + "/"));

		// A legitimate resource under the location is still served
		StepVerifier.create(function.apply(request("/resources/response.txt")))
				.expectNextCount(1)
				.expectComplete()
				.verify();

		// Encoded "//../": StringUtils#cleanPath cancels the ".." against the empty
		// path segment, while the file system does not, escaping the location
		expectEmpty(function, "/resources/%2F%2F..%2Fsecret.txt");
		expectEmpty(function, "/resources/%2F%2F%2E%2E%2Fsecret.txt");
		expectEmpty(function, "/resources/%252F%252F%252E%252E%252Fsecret.txt");

		// Encoded and double encoded "../"
		expectEmpty(function, "/resources/%2E%2E%2Fsecret.txt");
		expectEmpty(function, "/resources/%252E%252E%252Fsecret.txt");
		expectEmpty(function, "/resources/%2E%2E%2F%2E%2E%2Fsecret.txt");
	}

	@Test  // CVE-2024-38819
	public void rejectsEncodedBackslashPathTraversal() throws Exception {
		ClassPathResource location = new ClassPathResource("org/springframework/web/reactive/function/server/");
		PathResourceLookupFunction function = new PathResourceLookupFunction("/resources/**", location);

		// Encoded "\\..\": StringUtils#cleanPath cancels the ".." against the empty
		// path segment, while a file system with "\" as separator does not
		expectEmpty(function, "/resources/%5C%5C..%5Cresponse.txt");
		expectEmpty(function, "/resources/%5C%5C%2E%2E%5Cresponse.txt");
	}

	private void expectEmpty(PathResourceLookupFunction function, String requestUri) {
		StepVerifier.create(function.apply(request(requestUri)))
				.expectComplete()
				.verify();
	}

	private ServerRequest request(String requestUri) {
		// Use the URI variant to keep the raw, encoded request path as-is
		MockServerHttpRequest mockRequest =
				MockServerHttpRequest.method(HttpMethod.GET, URI.create("https://localhost" + requestUri)).build();
		return new DefaultServerRequest(MockServerWebExchange.from(mockRequest), Collections.emptyList());
	}

	@Test
	public void composeResourceLookupFunction() throws Exception {
		ClassPathResource defaultResource = new ClassPathResource("response.txt", getClass());

		Function<ServerRequest, Mono<Resource>> lookupFunction =
				new PathResourceLookupFunction("/resources/**",
						new ClassPathResource("org/springframework/web/reactive/function/server/"));

		Function<ServerRequest, Mono<Resource>> customLookupFunction =
				lookupFunction.andThen(resourceMono -> resourceMono
								.switchIfEmpty(Mono.just(defaultResource)));

		MockServerHttpRequest mockRequest = MockServerHttpRequest.get("https://localhost/resources/foo").build();
		ServerRequest request = new DefaultServerRequest(MockServerWebExchange.from(mockRequest), Collections.emptyList());

		Mono<Resource> result = customLookupFunction.apply(request);
		StepVerifier.create(result)
				.expectNextMatches(resource -> {
					try {
						return defaultResource.getFile().equals(resource.getFile());
					}
					catch (IOException ex) {
						return false;
					}
				})
				.expectComplete()
				.verify();
	}

}
