package com.spring_boot_backend;

import java.util.HashSet;
import java.util.Set;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.spring_boot_backend.entity.Authority;
import com.spring_boot_backend.entity.User;
import com.spring_boot_backend.repository.AuthorityRepository;
import com.spring_boot_backend.repository.UserRepository;

@SpringBootApplication
public class SpringBootBackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringBootBackendApplication.class, args);
	}

	@Bean
	CommandLineRunner run(AuthorityRepository authorityRepository, UserRepository userRepository,
			PasswordEncoder passwordEncoder) {
		return args -> {
			if (authorityRepository.findByAuthority("ADMIN").isPresent())
				return;

			Authority adminAuthority = authorityRepository.save(new Authority("ADMIN"));
			authorityRepository.save(new Authority("USER"));

			Set<Authority> authorities = new HashSet<>();

			authorities.add(adminAuthority);

			User adminUser = new User(1, "admin", passwordEncoder.encode("password"), authorities);

			userRepository.save(adminUser);
		};
	}

	@Bean
	public WebMvcConfigurer corsConfigurer() {
		return new WebMvcConfigurer() {
			public void addCorsMappings(CorsRegistry registry) {
				registry.addMapping("/**")
						.allowedMethods("*")
						.allowedOrigins("http://localhost:3000");
			}
		};
	}

}
