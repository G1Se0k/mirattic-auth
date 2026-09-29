package com.mirattic.auth;

import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.mysql.MySQLContainer;

/** One MySQL container and one Spring context shared by every test class. */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("local")
public abstract class IntegrationTest {

	static final MySQLContainer MYSQL = new MySQLContainer("mysql:8.4")
			.withUrlParam("preserveInstants", "true")
			.withUrlParam("connectionTimeZone", "UTC")
			.withUrlParam("forceConnectionTimeZoneToSession", "true");

	static {
		MYSQL.start();
	}

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry registry) throws Exception {
		registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
		registry.add("spring.datasource.username", MYSQL::getUsername);
		registry.add("spring.datasource.password", MYSQL::getPassword);
		Path dir = Files.createTempDirectory("mirattic-auth-key");
		registry.add("auth.signing-key.path", () -> dir.resolve("key.jwk.json").toString());
	}

	@MockitoBean
	protected JavaMailSender mailSender;

	@Autowired
	protected MockMvc mvc;

	@Autowired
	protected JdbcTemplate jdbc;
}
