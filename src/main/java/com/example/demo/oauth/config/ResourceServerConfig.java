package com.example.demo.oauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class ResourceServerConfig {

	// @formatter:off
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE + 1)
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.securityMatcher("/messages/**")
				.authorizeHttpRequests()
					.requestMatchers("/messages/**").hasAuthority("SCOPE_message.read")
					.and()
			.oauth2ResourceServer()
				.jwt();
		return http.build();
	}

	// // 这个很关键，给ResourceServer解码用，和认证的过程一样的解码
  // @Bean
  // JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
  //   return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  // }
	// @formatter:on
}