package onthelive.kr.authServer.service;

import jdk.jshell.execution.Util;
import lombok.RequiredArgsConstructor;
import onthelive.kr.authServer.entity.*;
import onthelive.kr.authServer.model.Client;
import onthelive.kr.authServer.repository.AuthorRepository;
import org.apache.coyote.Request;
import org.springframework.stereotype.Service;

import javax.persistence.NoResultException;
import javax.servlet.http.HttpServletRequest;
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
                ""
        );

        authorRepository.saveCode(codeEntity);
    }

    public void saveCode(String code, RequestEntity request, String scopes) {

        CodeEntity codeEntity = new CodeEntity(
                code,
                request.getRequestId(),
                request.getResponseType(),
                request.getRedirectUri(),
                request.getState(),
                request.getClientId(),
                scopes
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

}
