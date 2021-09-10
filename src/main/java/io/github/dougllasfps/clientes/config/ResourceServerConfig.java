package io.github.dougllasfps.clientes.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()       	
                .antMatchers("/api/usuarios").permitAll() // Para registro de usuário não precisa estar logado.
                .antMatchers(
                        "/api/clientes/**",
                        "/api/servicos-prestados/**").authenticated()
               .anyRequest().denyAll(); // Demais urls é para bloquear
        
        /* Projeto Spring Security Especialista do Dougllas
	    @Override
	    protected void configure( HttpSecurity http ) throws Exception {
	        http
	            .csrf().disable()
	            .authorizeRequests()
	                .antMatchers("/api/clientes/**")
	                    .hasAnyRole("USER", "ADMIN")
	                .antMatchers("/api/pedidos/**")
	                    .hasAnyRole("USER", "ADMIN")
	                .antMatchers("/api/produtos/**")
	                    .hasRole("ADMIN")
	                .antMatchers(HttpMethod.POST, "/api/usuarios/**")
	                    .permitAll()
	                .anyRequest().authenticated()
	            .and()
	                .sessionManagement()
	                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
	            .and()
	                .addFilterBefore( jwtFilter(), UsernamePasswordAuthenticationFilter.class);
	        ;
	    }        

         */

    }
}
