package com.example.demothymeleaf;


import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author ASUS
 */
@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //定制授权规则
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/css/**").permitAll()
                .antMatchers("/level1/**").hasRole("VIP1")
                .antMatchers("/level2/**").hasRole("VIP2")
                .antMatchers("/level3/**").hasRole("VIP3");
        //开启自动登录功能 如果访问被限制的页面，自动发起/login的请求
        http.formLogin();
        //
    }

    /**
     * 定义认证规则
     * 遇到错误 java.lang.IllegalArgumentException:
     * There is no PasswordEncoder mapped for the id "null"
     * 原因:id表示的是加密方式 它必须在password前面 spring-security拿到穿过来的密码会先查找这个{id}
     * 来确定以什么样的方式加密，如果查找不到就会认为是Null
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .passwordEncoder(new BCryptPasswordEncoder())
                .withUser("zhangsan")
                .password(new BCryptPasswordEncoder().encode("12345"))
                .roles("VIP1","VIP2")
                .and()
                .passwordEncoder(new BCryptPasswordEncoder())
                .withUser("lisi")
                .password(new BCryptPasswordEncoder().encode("12345"))
                .roles("VIP2")
                .and()
                .passwordEncoder(new BCryptPasswordEncoder())
                .withUser("wangwu")
                .password(new BCryptPasswordEncoder().encode("12345"))
                .roles("VIP3");
    }
}
