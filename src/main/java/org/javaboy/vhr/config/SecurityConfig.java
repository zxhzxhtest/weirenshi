package org.javaboy.vhr.config;


import com.fasterxml.jackson.databind.ObjectMapper;
import org.javaboy.vhr.model.Hr;
import org.javaboy.vhr.model.RespBean;
import org.javaboy.vhr.service.HrService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.*;

import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.security.auth.login.CredentialExpiredException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;


@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter{

    @Autowired
    HrService hrService;

    @Autowired
    CustomUrlDecisionManager customUrlDecisionManager;

    @Autowired
    CustomFilterInvocationSecurityMetadataSource customFilterInvocationSecurityMetadataSource;

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(hrService);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/login");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
//                .anyRequest().authenticated()
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {

                    @Override
                    public <O extends FilterSecurityInterceptor> O postProcess(O o) {
                        o.setAccessDecisionManager(customUrlDecisionManager);
                        o.setSecurityMetadataSource(customFilterInvocationSecurityMetadataSource);
                        return o;
                    }
                })
                .and()
                .formLogin()
                .usernameParameter("username")
                .passwordParameter("password")
                .loginProcessingUrl("/doLogin")
                .loginPage("/login")
                .successHandler(new AuthenticationSuccessHandler() {
                                    @Override
                                    public void onAuthenticationSuccess(HttpServletRequest req, HttpServletResponse resp, Authentication authentication) throws IOException, ServletException {

                                        resp.setContentType("application/json;charset=utf-8");
                                        PrintWriter out = resp.getWriter();
                                        Hr hr = (Hr) authentication.getPrincipal();

                                        hr.setPassword(null);
                                        RespBean ok = RespBean.ok("登陆成功！",hr);

                                        String s = new ObjectMapper().writeValueAsString(ok);
                                        out.write(s);
                                        out.flush();
                                        out.close();
                                    }
                                }
                )
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest req, HttpServletResponse resp, AuthenticationException e) throws IOException, ServletException {

                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter out = resp.getWriter();


                        RespBean resb = RespBean.error("登陆失败！");

                        if(e instanceof LockedException){

                           resb.setMsg("账户被锁定，请联系管理员！");
                       }else if(e instanceof CredentialsExpiredException){
                            resb.setMsg("密码过期，请联系管理员！");
                        }else if(e instanceof AccountExpiredException){
                            resb.setMsg("账户过期，请联系管理员！");
                        }else if(e instanceof DisabledException){
                            resb.setMsg("账户被禁用");
                        }else if(e instanceof BadCredentialsException){
                            resb.setMsg("用户名或密码输入错误");
                        }


                        out.write(new ObjectMapper().writeValueAsString(resb));
                        out.flush();
                        out.close();
                    }
                })
                .permitAll()
                .and()
                .logout()
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest req, HttpServletResponse resp, Authentication authentication) throws IOException, ServletException {

                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter out = resp.getWriter();

                        out.write(new ObjectMapper().writeValueAsString(RespBean.ok("注销成功")));
                        out.flush();
                        out.close();
                    }
                })
                .permitAll()
                .and()
                .csrf()
                .disable().exceptionHandling()
                //
                .authenticationEntryPoint(new AuthenticationEntryPoint() {
            @Override
            public void commence(HttpServletRequest req, HttpServletResponse resp, AuthenticationException e) throws IOException, ServletException {

                resp.setContentType("application/json;charset=utf-8");

                PrintWriter out = resp.getWriter();
                RespBean resb = RespBean.error("访问失败！");
                resp.setStatus(401);
                if(e instanceof InsufficientAuthenticationException){

                    resb.setMsg("尚未登录，请联系管理员！");
                }


                out.write(new ObjectMapper().writeValueAsString(resb));
                out.flush();
                out.close();
            }
        });
    }
}
