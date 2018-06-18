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
        /**
         * loginPage("/userLogin"); 自定义登陆页面 get请求
         * 如果定制了loginPage 那么loginPage的post请求就是登陆
         * 可以使用.loginProcessingUrl("/login");指定处理登陆逻辑的路径
         * 如果不指定 默认就是.loginPage("/userLogin") 我们自定义的路径
         * 如果是要验证密码  页面发送post请求到默认的/login路径让security验证用户名和密码,处理登陆逻辑
         */

        http.formLogin()
                .usernameParameter("username")
                .passwordParameter("password")
                //处理自定义登录页请求
                .loginPage("/userLogin")
                /**
                 *处理登陆逻辑的请求 这里如果不指定 默认是使用loginPage("/userLogin")的路径处理登陆逻辑
                 * 页面登陆的路径应该写"/userLogin" 否则跳转报错
                 */
                .loginProcessingUrl("/login");
        //开启自动配置登出功能 用户注销 清空session 设置注销成功返回首页
        http.logout().logoutSuccessUrl("/");
        //开启记住我 登陆成功会在浏览器本地存一个remember-me为键的cookie 注销会清楚cookie
        //rememberMeParameter("remember");设置页面Input框记住我的name参数属性值
        http.rememberMe().rememberMeParameter("remember");
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
