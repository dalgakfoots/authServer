package onthelive.kr.authServer.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import jdk.jshell.execution.Util;
import lombok.RequiredArgsConstructor;
import onthelive.kr.authServer.entity.*;
import onthelive.kr.authServer.model.Client;
import onthelive.kr.authServer.model.UserLoginProperty;
import onthelive.kr.authServer.repository.AuthorRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.coyote.Request;
import org.aspectj.apache.bcel.classfile.Code;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import javax.persistence.NoResultException;
import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthorService {

    private final AuthorRepository authorRepository;
    private final UtilService utilService;

    private final RSAKey initRsaKey; // onthelive.kr.authServer.configuration.RsaKeyGenerator.initRsaKey()

    @Value("${resourceServer.authenticationUrl}")
    private String autheticationUrl;

    public Client getClient(String clientId) {
        return authorRepository.getClient(clientId);
    }

    public void saveRequest(String reqId, HttpServletRequest request) {

        HashMap<String, String> temp = utilService.getGetMappingParameters(request);

        RequestEntity requestEntity = new RequestEntity(
                reqId,
                temp.get("response_type"),
                temp.get("redirect_uri"),
                temp.get("state"),
                temp.get("client_id")
        );

        authorRepository.saveRequest(requestEntity);
    }

    public RequestEntity getRequest(String reqId) {
        return authorRepository.getRequest(reqId);
    }

    public void removeRequest(String reqId) {
        authorRepository.removeRequest(reqId);
    }

    public void saveCode(String code, RequestEntity request) {

        CodeEntity codeEntity = new CodeEntity(
                code,
                request.getRequestId(),
                request.getResponseType(),
                request.getRedirectUri(),
                request.getState(),
                request.getClientId(),
                "",
                null
        );

        authorRepository.saveCode(codeEntity);
    }

    public void saveCode(String code, RequestEntity request, String scopes, String user) {

        CodeEntity codeEntity = new CodeEntity(
                code,
                request.getRequestId(),
                request.getResponseType(),
                request.getRedirectUri(),
                request.getState(),
                request.getClientId(),
                scopes,
                user
        );

        authorRepository.saveCode(codeEntity);
    }

    public CodeEntity getCode(String key) {
        return authorRepository.getCode(key);
    }

    public void removeCode(String key) {
        authorRepository.removeCode(key);
    }

    public TokenResponseEntity saveTokenResponse(TokenResponseEntity tokenResponse) {
        return authorRepository.saveTokenResponse(tokenResponse);
    }

    public TokenResponseEntity getTokenResponse(String clientId) {
        return authorRepository.getTokenResponse(clientId);
    }

    public void removeTokenResponseByRefreshToken(String refreshToken) {
        authorRepository.removeTokenResponseByRefreshToken(refreshToken);
    }

    public void removeTokenResponse(TokenResponseEntity tokenResponseEntity) {
        authorRepository.removeTokenResponse(tokenResponseEntity);
    }

    public ProtectedResourceEntity getProtectedResource(String id) {
        return authorRepository.getProtectedResource(id);
    }

    public TokenResponseEntity getTokenResponseByAccessToken(String accessToken) {
        return authorRepository.getTokenResponseByAccessToken(accessToken);
    }

    public String generateSerializedIdToken(CodeEntity code) throws JOSEException {

        // RS256 알고리즘의 비대칭 시그니처
        JWSSigner signer = new RSASSASigner(initRsaKey);

        HashMap<String,Object> payload = new HashMap<>();
        payload.put("iss","http://localhost:8091/");
        payload.put("sub", code.getUser());
        payload.put("aud",code.getClientId());
        payload.put("iat", new Date().getTime());
        payload.put("exp", new Date().getTime() + (1000 * 60 * 5));

        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(initRsaKey.getKeyID()).build(),
                new Payload(payload)
        );

        jwsObject.sign(signer);

        return jwsObject.serialize();
    }

    public UserEntity getUser(String user) {
        return authorRepository.getUser(user);
    }

    public UserLoginProperty getAuthenticatedUser(HttpServletRequest request) {
        String email = request.getParameter("email");
        String password = request.getParameter("password");

        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "application/x-www-form-urlencoded");
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("email", email);
        body.add("password", password);

        HttpEntity entity = new HttpEntity(body, headers);

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<HashMap> response = null;

        try {
            response = restTemplate.postForEntity(autheticationUrl, entity, HashMap.class);
        } catch (HttpClientErrorException.Unauthorized e){
            return new UserLoginProperty("", false);
        } catch (Exception e){
            e.printStackTrace();
            return new UserLoginProperty("", false);
        }

        if (response.getStatusCodeValue() >= 200 && response.getStatusCodeValue() < 300) {
            return new UserLoginProperty((String)response.getBody().get("email") , (boolean)response.getBody().get("authenticated"));
        }

        return new UserLoginProperty("",false);
    }
}
