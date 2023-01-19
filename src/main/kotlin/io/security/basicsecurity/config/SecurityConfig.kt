package io.security.basicsecurity.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.SecurityFilterChain

@Configuration
@EnableWebSecurity
class SecurityConfig(
    private val userDetailsService: UserDetailsService
) {

    @Bean
    fun filterChain(http: HttpSecurity) : SecurityFilterChain {
        http.authorizeRequests {
            it.anyRequest().authenticated()
        }
        http.formLogin {
            it.defaultSuccessUrl("/")
            it.failureUrl("/login")
            it.loginProcessingUrl("/login_proc")
            it.successHandler { request, response, authentication ->
                println("authentication: ${authentication.name}")
                response.sendRedirect("/")
            }
            it.failureHandler { request, response, exception ->
                println("exception: ${exception.message}")
                response.sendRedirect("/login")
            }
            it.permitAll()
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

        //세션이 만료되고 웹브라우저가 종료된 후에도 어플리케이션이 사용자를 기억하는 기능
        http.rememberMe {
            println("remember-me")
            it.rememberMeParameter("remember") // 기본 파라미터명은 remember-me
            it.tokenValiditySeconds(3600) // default 14일
            // it.alwaysRemember(true) // 로그인시 무조건 리멤버미 기능 활성화
            it.userDetailsService(userDetailsService) // 내부적으로 재인증 처리를 위해서 필요함
        }

        http.sessionManagement {
            // 세션 제어 전략
            // 1. 이전 사용자의 세션을 만료시킴 - maxSessionsPreventsLogin(true)
            // 2. 현재 사용자의 인증을 실패시킴 - maxSessionsPreventsLogin(false)
            it.maximumSessions(1) // -1: 로그인 세션 무제한 허용
                .maxSessionsPreventsLogin(true)
                .expiredUrl("/expired")
            it.invalidSessionUrl("/invalid")
        }

        return http.build()
    }


}