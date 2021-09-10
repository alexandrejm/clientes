package io.github.dougllasfps.clientes.rest;

import javax.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import io.github.dougllasfps.clientes.exception.UsuarioCadastradoException;
import io.github.dougllasfps.clientes.model.entity.Usuario;
import io.github.dougllasfps.clientes.service.UsuarioService;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/usuarios")
@RequiredArgsConstructor
public class UsuarioController {

    private final UsuarioService service;
    //private final PasswordEncoder passwordEncoder;

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public void salvar(@RequestBody @Valid Usuario usuario){
    	
    	//BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    	
        try{
        	//String senhaCriptografada = passwordEncoder.encode(usuario.getPassword());
            //usuario.setPassword(senhaCriptografada);
            service.salvar(usuario);
        }catch (UsuarioCadastradoException e){
            throw new ResponseStatusException( HttpStatus.BAD_REQUEST, e.getMessage() );
        }
    }
    
    /* Curso Spring Securit Especialista do Dougllas
    private final PasswordEncoder passwordEncoder;
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Usuario salvar( @RequestBody @Valid Usuario usuario ){
        String senhaCriptografada = passwordEncoder.encode(usuario.getSenha());
        usuario.setSenha(senhaCriptografada);
        return usuarioService.salvar(usuario);
    }
     */
    
    
}
