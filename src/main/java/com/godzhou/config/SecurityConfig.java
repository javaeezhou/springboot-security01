package com.godzhou.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

//Aop  : 拦截器！
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //授权
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //首页所有人都能访问，功能页是由对应权限的人才能访问
        //请求授权的规则~
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasAnyRole("vip1")
                .antMatchers("/level2/**").hasAnyRole("vip2")
                .antMatchers("/level3/**").hasAnyRole("vip3");

        //没有权限默认回调到登录页面
        //开启 以及定制登录页面 和定义请求表单用户名和密码的name 和login真实请求url
        http.formLogin().loginPage("/toLogin").usernameParameter("uname").passwordParameter("pwd").loginProcessingUrl("/login");
//        http.formLogin();

        //关闭csrf攻击保护  springboot2.0.x集成的security版本没有做logout保护（都是get请求但是高版本做了logout重定向post请求)
        //貌似定制了登录页面和开启这个配置之后重定向保护就没了 ----> 所以要定制登录页面那么这个配置必须开
        http.csrf().disable();

        //开启注销 还有注销之后删除cookie和session的操作
        http.logout().logoutSuccessUrl("/");

        //开启密码记住我模式
        http.rememberMe().rememberMeParameter("remember");

        //定制登录页面
    }

    //认证
    //springboot2.1.x以上 security5 必须指定密码编码
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //内存中定义用户
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("godzhou").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2").and()
                .withUser("root").password(new BCryptPasswordEncoder().encode("111111")).roles("vip1","vip2","vip3").and()
                .withUser("guest").password(new BCryptPasswordEncoder().encode("222222")).roles("vip3","vip2");

    }
}
