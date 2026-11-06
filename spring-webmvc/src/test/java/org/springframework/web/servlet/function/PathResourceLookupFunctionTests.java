/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.web.servlet.function;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Optional;
import java.util.function.Function;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.web.testfixture.servlet.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Arjen Poutsma
 */
public class PathResourceLookupFunctionTests {

	@Test
	public void normal() throws Exception {
		ClassPathResource location =
				new ClassPathResource("org/springframework/web/servlet/function/");

		PathResourceLookupFunction function =
				new PathResourceLookupFunction("/resources/**", location);

		MockHttpServletRequest servletRequest =
				new MockHttpServletRequest("GET", "/resources/response.txt");
		ServerRequest request = new DefaultServerRequest(servletRequest, Collections.emptyList());

		Optional<Resource> result = function.apply(request);
		assertThat(result.isPresent()).isTrue();

		File expected = new ClassPathResource("response.txt", getClass()).getFile();
		assertThat(result.get().getFile()).isEqualTo(expected);
	}

	@Test
	public void subPath() throws Exception {
		ClassPathResource location =
				new ClassPathResource("org/springframework/web/servlet/function/");

		PathResourceLookupFunction function =
				new PathResourceLookupFunction("/resources/**", location);

		MockHttpServletRequest servletRequest =
				new MockHttpServletRequest("GET", "/resources/child/response.txt");
		ServerRequest request = new DefaultServerRequest(servletRequest, Collections.emptyList());

		Optional<Resource> result = function.apply(request);
		assertThat(result.isPresent()).isTrue();

		File expected =
				new ClassPathResource("org/springframework/web/servlet/function/child/response.txt")
						.getFile();
		assertThat(result.get().getFile()).isEqualTo(expected);
	}

	@Test
	public void notFound() {
		ClassPathResource location =
				new ClassPathResource("org/springframework/web/reactive/function/server/");

		PathResourceLookupFunction function =
				new PathResourceLookupFunction("/resources/**", location);

		MockHttpServletRequest servletRequest =
				new MockHttpServletRequest("GET", "/resources/foo.txt");
		ServerRequest request = new DefaultServerRequest(servletRequest, Collections.emptyList());

		Optional<Resource> result = function.apply(request);
		assertThat(result.isPresent()).isFalse();
	}

	@Test  // CVE-2024-38819
	public void rejectsEncodedPathTraversal(@TempDir Path temporaryFolder) throws Exception {
		Files.write(temporaryFolder.resolve("secret.txt"), "secret".getBytes(StandardCharsets.UTF_8));
		Path locationFolder = Files.createDirectory(temporaryFolder.resolve("public"));
		Files.write(locationFolder.resolve("response.txt"), "public".getBytes(StandardCharsets.UTF_8));

		PathResourceLookupFunction function = new PathResourceLookupFunction("/resources/**",
				new FileSystemResource(locationFolder.toString() + "/"));

		// A legitimate resource under the location is still served
		assertThat(function.apply(request("/resources/response.txt"))).isPresent();

		// Encoded "//../": StringUtils#cleanPath cancels the ".." against the empty
		// path segment, while the file system does not, escaping the location
		assertThat(function.apply(request("/resources/%252F%252F..%252Fsecret.txt"))).isEmpty();
		assertThat(function.apply(request("/resources/%252F%252F%252E%252E%252Fsecret.txt"))).isEmpty();
		assertThat(function.apply(request("/resources/%2F%2F%2E%2E%2Fsecret.txt"))).isEmpty();

		// Encoded and double encoded "../"
		assertThat(function.apply(request("/resources/%2E%2E%2Fsecret.txt"))).isEmpty();
		assertThat(function.apply(request("/resources/%252E%252E%252Fsecret.txt"))).isEmpty();
		assertThat(function.apply(request("/resources/%2E%2E%2F%2E%2E%2Fsecret.txt"))).isEmpty();
	}

	@Test  // CVE-2024-38819
	public void rejectsEncodedBackslashPathTraversal() throws Exception {
		ClassPathResource location = new ClassPathResource("org/springframework/web/servlet/function/");
		PathResourceLookupFunction function = new PathResourceLookupFunction("/resources/**", location);

		// Encoded "\\..\": StringUtils#cleanPath cancels the ".." against the empty
		// path segment, while a file system with "\" as separator does not
		assertThat(function.apply(request("/resources/%5C%5C..%5Cresponse.txt"))).isEmpty();
		assertThat(function.apply(request("/resources/%255C%255C..%255Cresponse.txt"))).isEmpty();
		assertThat(function.apply(request("/resources/%255C%255C%252E%252E%255Cresponse.txt"))).isEmpty();
	}

	@Test  // CVE-2026-41843
	public void rejectsProtectedDirectoryRegardlessOfCase(@TempDir Path temporaryFolder) throws Exception {
		Path locationFolder = Files.createDirectory(temporaryFolder.resolve("public"));
		Files.write(locationFolder.resolve("response.txt"), "public".getBytes(StandardCharsets.UTF_8));
		Path webInf = Files.createDirectory(locationFolder.resolve("web-inf"));
		Files.write(webInf.resolve("web.xml"), "secret".getBytes(StandardCharsets.UTF_8));
		Path metaInf = Files.createDirectory(locationFolder.resolve("meta-inf"));
		Files.write(metaInf.resolve("MANIFEST.MF"), "secret".getBytes(StandardCharsets.UTF_8));

		PathResourceLookupFunction function = new PathResourceLookupFunction("/resources/**",
				new FileSystemResource(locationFolder.toString() + "/"));

		// A legitimate resource under the location is still served
		assertThat(function.apply(request("/resources/response.txt"))).isPresent();

		// Lower/mixed case variants of the protected directories must be rejected
		assertThat(function.apply(request("/resources/web-inf/web.xml"))).isEmpty();
		assertThat(function.apply(request("/resources/Web-Inf/web.xml"))).isEmpty();
		assertThat(function.apply(request("/resources/meta-inf/MANIFEST.MF"))).isEmpty();
		assertThat(function.apply(request("/resources/Meta-Inf/MANIFEST.MF"))).isEmpty();

		// ... including encoded variants
		assertThat(function.apply(request("/resources/%77eb-inf/web.xml"))).isEmpty();
		assertThat(function.apply(request("/resources/%6Deta-inf/MANIFEST.MF"))).isEmpty();
	}

	private ServerRequest request(String requestUri) {
		return new DefaultServerRequest(
				new MockHttpServletRequest("GET", requestUri), Collections.emptyList());
	}

	@Test
	public void composeResourceLookupFunction() throws Exception {
		ClassPathResource defaultResource = new ClassPathResource("response.txt", getClass());

		Function<ServerRequest, Optional<Resource>> lookupFunction =
				new PathResourceLookupFunction("/resources/**",
						new ClassPathResource("org/springframework/web/servlet/function/"));

		Function<ServerRequest, Optional<Resource>> customLookupFunction =
				lookupFunction.andThen((Optional<Resource> optionalResource) -> {
					if (optionalResource.isPresent()) {
						return optionalResource;
					}
					else {
						return Optional.of(defaultResource);
					}
				});

		MockHttpServletRequest servletRequest = new MockHttpServletRequest("GET", "/resources/foo");
		ServerRequest request = new DefaultServerRequest(servletRequest, Collections.emptyList());

		Optional<Resource> result = customLookupFunction.apply(request);
		assertThat(result.isPresent()).isTrue();

		assertThat(result.get().getFile()).isEqualTo(defaultResource.getFile());
	}

}
