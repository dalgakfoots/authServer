package onthelive.kr.authServer.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import jdk.jshell.execution.Util;
import lombok.RequiredArgsConstructor;
import onthelive.kr.authServer.entity.*;
import onthelive.kr.authServer.model.Client;
import onthelive.kr.authServer.repository.AuthorRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.coyote.Request;
import org.aspectj.apache.bcel.classfile.Code;
import org.springframework.stereotype.Service;

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

    public void saveCode(String code, RequestEntity request, String scopes, UserEntity user) {

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
        String stringSharedSecret = "shared OAuth token secret!shared OAuth token secret!shared OAuth token secret!shared OAuth token secret!shared OAuth token secret!shared OAuth token secret!shared OAuth token secret!shared OAuth token secret!shared OAuth token secret!shared OAuth token secret!";
        byte[] sharedSecret = stringSharedSecret.getBytes();

        HashMap<String,Object> payload = new HashMap<>();
        payload.put("iss","http://localhost:8091/");
        payload.put("sub", code.getUser().getSub());
        payload.put("aud",code.getClientId());
        payload.put("iat", new Date().getTime());
        payload.put("exp", new Date().getTime() + (1000 * 60 * 5));

        JWSSigner signer = new MACSigner(sharedSecret);

        JWSObject jwsObject = new JWSObject(
                new JWSHeader(JWSAlgorithm.HS256), new Payload(payload)
        );

        jwsObject.sign(signer);

        return jwsObject.serialize();
    }

    public UserEntity getUser(String user) {
        return authorRepository.getUser(user);
    }
}
