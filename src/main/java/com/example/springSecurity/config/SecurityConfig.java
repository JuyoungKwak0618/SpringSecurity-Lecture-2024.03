package com.example.springSecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import com.example.springSecurity.service.MyOAuth2UserService;

import jakarta.servlet.DispatcherType;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	@Autowired private MyOAuth2UserService myOAuth2UserService;

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf(auth -> auth.disable())				// 괄호 안에 람다함수를 사용해야 함
			.headers(x -> x.frameOptions(y -> y.disable()))	// CK Editor image upload
			.authorizeHttpRequests(auth -> auth
					.dispatcherTypeMatchers(DispatcherType.FORWARD).permitAll()
					.requestMatchers("/user/register",
							"/img/**", "/css/**", "/js/**", "/error/**").permitAll()
					.requestMatchers("/admin/**").hasAuthority("ROLE_ADMIN")
					.anyRequest().authenticated()
			)
			.formLogin(auth -> auth
				.loginPage("/user/login")			// 로그인 폼
				.loginProcessingUrl("/user/login")		// 내가 만드는 것이 아님. 스프링시큐리티가 낚아 챔. UserDetailsService 구현 객체에서 처리해주여야 함 
				.usernameParameter("uid")
				.passwordParameter("pwd")
				.defaultSuccessUrl("/user/loginSuccess", true)		// 내가 로그인 후 해야할 일, 예) 세션 세팅, 오늘의 메세지 등
				.permitAll()
			)
			.oauth2Login(auth -> auth
					.loginPage("/user/login")
					// 소셜 로그인이 완료된 이후의 후처리
					// 1. 코드받기(인증), 2. 액세스 토큰(권한), 3. 사용자 프로필 정보를 가져옴
					// 4. 3에서 받은 정보를 토대로 DB에 없으면 가입을 시켜줌
					// 5. 프로바이더가 제공하는 정보 + 추가정보 수집 (주소, ...)
					.userInfoEndpoint(user -> user.userService(myOAuth2UserService))
					.defaultSuccessUrl("/user/loginSuccess", true)	
			)
			.logout(auth -> auth
				.logoutUrl("/user/logout")
				.invalidateHttpSession(true)			// 로그아웃시 세션 초기화
				.deleteCookies("jSESSIONID") 			// 로구아웃시 쿠키 삭제
				.logoutSuccessUrl("/user/login")
			);
		return http.build();
		
	}
	
}
