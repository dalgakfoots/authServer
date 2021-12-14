package onthelive.kr.authServer.controller;

import lombok.RequiredArgsConstructor;
import onthelive.kr.authServer.entity.ClientEntity;
import onthelive.kr.authServer.model.Client;
import onthelive.kr.authServer.model.Registration;
import onthelive.kr.authServer.service.AuthorService;
import onthelive.kr.authServer.service.ClientService;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Date;

@RestController
@RequiredArgsConstructor
public class ClientRegistrationController {

    private final ClientService clientService;
    private final AuthorService authorService;

    @PostMapping("/register")
    public ResponseEntity postRegister(HttpServletRequest request) {

        Registration register = new Registration();
        register.setRedirect_uris(request.getParameter("redirect_uris"));
        register.setScope(request.getParameter("scope"));
        register.setToken_endpoint_auth_method(request.getParameter("token_endpoint_auth_method"));
        register.setGrant_types(request.getParameter("grant_types"));
        register.setResponse_types(request.getParameter("response_types"));

        ResponseEntity<ClientEntity> checkClientMetadata = clientService.checkClientMetadata(register);
        ClientEntity client = checkClientMetadata.getBody();

        if (checkClientMetadata.hasBody() && checkClientMetadata.getStatusCodeValue() == 200) {
            client.setClientId(RandomStringUtils.randomAlphanumeric(8));
            client.setClientSecret(RandomStringUtils.randomAlphanumeric(8));
            client.setClientIdCreatedAt(new Date().getTime());
            client.setClientSecretExpiresAt(0L);
            client.setRegistrationAccessToken(RandomStringUtils.randomAlphanumeric(8));
            client.setRegistrationClientUri("http://localhost:8091/register/" + client.getClientId());
            clientService.saveClient(client);

            Registration registration = new Registration(
                    client.getClientId(),
                    client.getClientSecret(),
                    client.getRedirectUri(),
                    client.getScopes(),
                    client.getTokenEndpointAuthMethod(),
                    client.getGrantTypes(),
                    client.getResponseTypes(),
                    client.getClientIdCreatedAt(),
                    client.getClientSecretExpiresAt(),
                    client.getRegistrationAccessToken(),
                    client.getRegistrationClientUri()
            );

            return new ResponseEntity(registration, HttpStatus.CREATED);
        }

        return new ResponseEntity(checkClientMetadata.getStatusCode());
    }

    @GetMapping("/register/{clientId}")
    public ResponseEntity<Registration> getRegister(HttpServletRequest request,
                            @PathVariable(name = "clientId") String clientId){
        ResponseEntity<ClientEntity> responseEntity = clientService.authorizeConfigurationEndpointRequest(request, clientId);
        ClientEntity clientEntity = responseEntity.getBody();

        if(clientEntity == null){
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

        Registration registration = new Registration(
                clientEntity.getClientId(),
                clientEntity.getClientSecret(),
                clientEntity.getRedirectUri(),
                clientEntity.getScopes(),
                clientEntity.getTokenEndpointAuthMethod(),
                clientEntity.getGrantTypes(),
                clientEntity.getResponseTypes(),
                clientEntity.getClientIdCreatedAt(),
                clientEntity.getClientSecretExpiresAt(),
                clientEntity.getRegistrationAccessToken(),
                clientEntity.getRegistrationClientUri()
        );
        return new ResponseEntity<>(registration, HttpStatus.OK);
    }

    @PutMapping("/register/{clientId}")
    public ResponseEntity putRegister(HttpServletRequest request,
                            @PathVariable(name = "clientId") String clientId){
        ResponseEntity<ClientEntity> responseEntity = clientService.authorizeConfigurationEndpointRequest(request, clientId);
        ClientEntity clientEntity = responseEntity.getBody();
        System.out.println("clientEntity = " + clientEntity);

        if(!request.getParameter("client_id").equals(clientEntity.getClientId())){
            return new ResponseEntity(HttpStatus.BAD_REQUEST);
        }

        if(request.getParameter("client_secret") == null
                && !request.getParameter("client_secret").equals(clientEntity.getClientSecret())){
            return new ResponseEntity(HttpStatus.BAD_REQUEST);
        }


        // 현재 clientEntity 는 clientId에 해당하는 모든 정보를 가지고 있다.
        // request 에는 clientEntity의 정보 중 변경하고자 하는 정보를 가지고 있다.

        Registration registration = new Registration();
        registration.setGrant_types(request.getParameter("grant_types"));
        registration.setResponse_types(request.getParameter("response_types"));
        registration.setRedirect_uris(request.getParameter("redirect_uris"));
        registration.setScope(request.getParameter("scope"));

        System.out.println("registration = " + registration);

        ResponseEntity<ClientEntity> checkClientMetadata = clientService.checkClientMetadata(registration);
        // TODO status code check !
        System.out.println("checkClientMetadata.getStatusCodeValue() = " + checkClientMetadata.getStatusCodeValue());
        ClientEntity checkedClientMetaData = checkClientMetadata.getBody();

        System.out.println("checkedClientMetaData = " + checkedClientMetaData);

        Registration modifyResult = clientService.modifyClient(checkedClientMetaData, clientEntity);

        if (modifyResult.getClient_id() == null) {
            return new ResponseEntity(HttpStatus.BAD_REQUEST);
        }

        return new ResponseEntity(modifyResult, HttpStatus.OK);
    }

    @DeleteMapping("/register/{clientId}")
    public ResponseEntity deleteRegister(HttpServletRequest request,
                               @PathVariable(name = "clientId") String clientId){
        ResponseEntity<ClientEntity> responseEntity = clientService.authorizeConfigurationEndpointRequest(request, clientId);
        ClientEntity clientEntity = responseEntity.getBody();

        clientService.deleteClient(clientEntity);

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }
}
