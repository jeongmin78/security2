package io.security.basicsecurity.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.savedrequest.HttpSessionRequestCache

@Configuration
@EnableWebSecurity
class SecurityConfig(
//    private val userDetailsService: UserDetailsService
) {

    @Bean
    fun users(): UserDetailsService {
        val user = User.builder()
            .username("user")
            .password("{noop}1234")
            .roles("USER")
            .build()
        val sys = User.builder()
            .username("sys")
            .password("{noop}1234")
            .roles("SYS")
            .build()
        val admin = User.builder()
            .username("admin")
            .password("{noop}1234")
            .roles("ADMIN")
            .build()
        return InMemoryUserDetailsManager(user, sys, admin)
    }

    @Bean
    fun filterChain(http: HttpSecurity) : SecurityFilterChain {

        http.authorizeRequests {
            // 구체적인 경로가 먼저 오고 그것보다 큰 범위의 경로가 뒤에 오도록 해야 한다
            it.antMatchers("/login").permitAll()
            it.antMatchers("/user").hasRole("USER")
            it.antMatchers("/admin/pay").hasRole("ADMIN")
            it.antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')") // access 사용하면 SpEL 표현식 사용 가능
            it.anyRequest().authenticated()
        }

        http.formLogin {
            it.defaultSuccessUrl("/")
            it.failureUrl("/login")
            it.loginProcessingUrl("/login_proc")
            it.successHandler { request, response, authentication ->
                println("authentication: ${authentication.name}")
                response.sendRedirect("/")

                val requestCache = HttpSessionRequestCache()
                val savedRequest = requestCache.getRequest(request, response)
                val redirectUrl = savedRequest.redirectUrl
                response.sendRedirect(redirectUrl)
            }
            it.failureHandler { request, response, exception ->
                println("exception: ${exception.message}")
                response.sendRedirect("/login")
            }
            it.permitAll()
        }

        http.exceptionHandling {
            // authenticationEntryPoint 구현시 formLogin 기본 /login 경로가 동작하지 않음
//            it.authenticationEntryPoint { request, response, authException ->
//                response.sendRedirect("/login")
//            }
            it.accessDeniedHandler { request, response, accessDeniedException ->
                response.sendRedirect("/denied")
            }
        }

        http.logout {
            it.logoutUrl("/logout")
            it.logoutSuccessUrl("/login")
            it.deleteCookies("JSESSIONID") // 로그아웃 후 쿠키 삭제
            it.addLogoutHandler { request, response, authentication ->
                val session = request.session
                session.invalidate()
            }
            it.logoutSuccessHandler { request, response, authentication ->
                response.sendRedirect("/login")
            }
        }
//
//        //세션이 만료되고 웹브라우저가 종료된 후에도 어플리케이션이 사용자를 기억하는 기능
//        http.rememberMe {
//            println("remember-me")
//            it.rememberMeParameter("remember") // 기본 파라미터명은 remember-me
//            it.tokenValiditySeconds(3600) // default 14일
//            // it.alwaysRemember(true) // 로그인시 무조건 리멤버미 기능 활성화
//            it.userDetailsService(userDetailsService) // 내부적으로 재인증 처리를 위해서 필요함
//        }
//
//        http.sessionManagement {
//            // 세션 제어 전략
//            // 1. 이전 사용자의 세션을 만료시킴 - maxSessionsPreventsLogin(true)
//            // 2. 현재 사용자의 인증을 실패시킴 - maxSessionsPreventsLogin(false)
//            it.maximumSessions(1) // -1: 로그인 세션 무제한 허용
//                .maxSessionsPreventsLogin(true)
//                .expiredUrl("/expired")
//            it.invalidSessionUrl("/invalid")
//            it.sessionFixation().changeSessionId() // 기본값
//            // .none(), .migrateSession(), .newSession()
//            it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션이 없는 인증방식(jwt 등)을 이용하려면 STATELESS 속성 사용
//        }

        return http.build()
    }


}