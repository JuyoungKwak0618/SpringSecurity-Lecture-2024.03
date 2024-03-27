package com.example.springSecurity.service;

import java.util.Map;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.example.springSecurity.entity.MyUserDetails;
import com.example.springSecurity.entity.SecurityUser;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
@Slf4j
@Service
@RequiredArgsConstructor
public class MyOAuth2UserService extends DefaultOAuth2UserService{
	private final SecurityUserService securityService;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;
	
	// Provider(구글, 깃허브 등)로부터 받은 userRequest 데이터에 대해서 후처리하는 메소드
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		String uid, email, uname, picture;
		String hashedPwd = bCryptPasswordEncoder.encode("social Login");
		SecurityUser securityUser = null;
		
		OAuth2User oAuth2User = super.loadUser(userRequest);
		log.info("getAttributes():" + oAuth2User.getAttributes());
		
		String provider = userRequest.getClientRegistration().getRegistrationId();
		switch (provider) {
		case "google":
			String providerId = oAuth2User.getAttribute("sub");
			uid = provider + "_" + providerId;
			securityUser = securityService.getUserByUid(uid);
			if (securityUser == null) {				// 가입이 안되어있으므로 가입 진행
				uname = oAuth2User.getAttribute("name");
				uname = (uname == null) ? "google_user" : uname;
				email = oAuth2User.getAttribute("email");
				picture = oAuth2User.getAttribute("picture");
				securityUser = SecurityUser.builder()
								.uid(uid).pwd(hashedPwd).uname(uname).email(email).picture(picture)
								.provider(provider).build();
				securityService.insertSecurityUser(securityUser);
				securityUser = securityService.getUserByUid(uid);
				log.info("구글 계정을 통해 회원가입이 되었습니다.");
			}
			break;
			
		case "github":
			int id = oAuth2User.getAttribute("id");
			uid = provider + "_" + id;
			securityUser = securityService.getUserByUid(uid);
			if (securityUser == null) {				// 가입이 안되어있으므로 가입 진행
				uname = oAuth2User.getAttribute("name");
				uname = (uname == null) ? "github_user" : uname;
				email = oAuth2User.getAttribute("email");
				picture = oAuth2User.getAttribute("avatar_url");
				securityUser = SecurityUser.builder()
								.uid(uid).pwd(hashedPwd).uname(uname).email(email).picture(picture)
								.provider(provider).build();
				securityService.insertSecurityUser(securityUser);
				securityUser = securityService.getUserByUid(uid);
				log.info("깃허브 계정을 통해 회원가입이 되었습니다.");
			}
			break;
		
		case "naver":
			Map<String, Object> response = (Map) oAuth2User.getAttribute("response");
			String nid = (String) response.get("id");
			uid = provider + "_" + nid;
			securityUser = securityService.getUserByUid(uid);
			if (securityUser == null) {				// 가입이 안되어있으므로 가입 진행
				uname = (String) response.get("nickname");
				uname = (uname == null) ? "naver_user" : uname;
				email = oAuth2User.getAttribute("email");
				picture = oAuth2User.getAttribute("profile_image");
				securityUser = SecurityUser.builder()
								.uid(uid).pwd(hashedPwd).uname(uname).email(email).picture(picture)
								.provider(provider).build();
				securityService.insertSecurityUser(securityUser);
				securityUser = securityService.getUserByUid(uid);
				log.info("네이버 계정을 통해 회원가입이 되었습니다.");
			}
			break;
			
		case "kakao":
			long kid = (long) oAuth2User.getAttribute("id");
			uid = provider + "_" + kid;
			securityUser = securityService.getUserByUid(uid);
			if (securityUser == null) {				// 가입이 안되어있으므로 가입 진행
				Map<String, String> properties = (Map) oAuth2User.getAttribute("properties");
				Map<String, Object> account = (Map) oAuth2User.getAttribute("kakao_account");
				uname = (String) properties.get("nickname");
				uname = (uname == null) ? "kakao_user" : uname;
				email = "rmmr123@naver.com";
				picture = properties.get("profile_image");
				securityUser = SecurityUser.builder()
								.uid(uid).pwd(hashedPwd).uname(uname).email(email).picture(picture)
								.provider(provider).build();
				securityService.insertSecurityUser(securityUser);
				securityUser = securityService.getUserByUid(uid);
				log.info("카카오 계정을 통해 회원가입이 되었습니다.");
			}
			break;
			
		case "facebook":
			String fid = oAuth2User.getAttribute("id");
			uid = provider + "_" + fid;
			securityUser = securityService.getUserByUid(uid);
			if (securityUser == null) {				// 가입이 안되어있으므로 가입 진행
				uname = oAuth2User.getAttribute("name");
				uname = (uname == null) ? "facebook_user" : uname;
				email = oAuth2User.getAttribute("email");
				picture = oAuth2User.getAttribute("public_profile");
				securityUser = SecurityUser.builder()
								.uid(uid).pwd(hashedPwd).uname(uname).email(email).picture(picture)
								.provider(provider).build();
				securityService.insertSecurityUser(securityUser);
				securityUser = securityService.getUserByUid(uid);
				log.info("페이스북 계정을 통해 회원가입이 되었습니다.");
			}
		}
		return new MyUserDetails(securityUser, oAuth2User.getAttributes());
	}

}
