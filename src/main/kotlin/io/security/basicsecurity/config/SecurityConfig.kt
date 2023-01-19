package io.security.basicsecurity.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain

@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    fun filterChain(http: HttpSecurity) : SecurityFilterChain {
        http.authorizeRequests {
            it.anyRequest().authenticated()
        }
        http.formLogin {
            it.loginPage("/login")
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

        return http.build()
    }


}