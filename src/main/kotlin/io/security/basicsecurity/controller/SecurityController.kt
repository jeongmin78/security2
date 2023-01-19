package io.security.basicsecurity.controller

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class SecurityController {

    @GetMapping("login-page")
    fun loginPage() : String {
        return "loginPage"
    }
}