package onthelive.kr.authServer.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import onthelive.kr.authServer.entity.*;
import onthelive.kr.authServer.model.Client;
import onthelive.kr.authServer.model.TokenResponse;
import onthelive.kr.authServer.service.AuthorService;
import onthelive.kr.authServer.service.UtilService;
import org.apache.commons.lang3.RandomStringUtils;
import org.json.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.LocalDateTime;
import java.util.*;

@Controller
@RequiredArgsConstructor
@Log4j2
public class AuthorAndAuthenController {

    private final UtilService utilService;
    private final AuthorService authorService;

    private static HashMap memDB = new HashMap();

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("error", "access denied");
        return "/error";

    }

    /*
     * 인가 엔드포인트 :
     * 클라이언트App 이 인가서버 에 등록되어 있는지 확인하고,
     * 사용자를 인가 승인/거부 화면으로 이동시킨다.
     * */
    @GetMapping("/authorize") // 인가 엔드포인트
    public String getAuthorize(HttpServletRequest httpRequest, RedirectAttributes attributes, Model model) {
        String clientId = httpRequest.getParameter("client_id");
        String scopes = httpRequest.getParameter("scope");

        Client client = authorService.getClient(clientId);
        List requestScopes = utilService.getScopes(scopes);
        List clientScopes = utilService.getScopes(client.getScopes());

        List temp = new ArrayList(requestScopes);
        Collections.copy(temp , requestScopes);
        temp.removeAll(clientScopes);

        if (client.getClientId().equals("")) {
            log.error("알 수 없는 Client Id 접근 " + clientId);
            model.addAttribute("error", "Unknown Client Id");
            return "/error";
        } else if (temp.size() > 0) {
            log.error("invalid scope error in /authorize");
            attributes.addAttribute("error", "invalid_scope");
            return "redirect:"+client.getRedirectUri();
        } else {
            String reqId = RandomStringUtils.randomAlphanumeric(8);
            authorService.saveRequest(reqId, httpRequest);

            model.addAttribute("client", client);
            model.addAttribute("reqId", reqId);
            model.addAttribute("scope", scopes);
            return "/approve";
        }
    }

    /*
     * 리소스소유자(사용자)의 권한 위임 요청 처리 :
     * 사용자가 권한 위임 요청을 승인할 시, 클라이언트 App이 등록한 Redirect uri 를 통해 제어를 넘겨준다.
     * 이후 /token 으로의 접근을 대기한다.
     * */
    @PostMapping("/approve") // 권한 위임을 위한 요청 처리
    public String postApprove(HttpServletRequest httpRequest, RedirectAttributes attributes, Model model) {
        String reqId = httpRequest.getParameter("reqId");

        RequestEntity request = authorService.getRequest(reqId);
        authorService.removeRequest(reqId);

        if (request == null) {
            model.addAttribute("error", "No matching authorization request");
            return "/error";
        }

        if (!httpRequest.getParameter("approve").equals("")) {

            if (request.getResponseType().equals("code")) {

                List requestScopes = utilService.getScopes(httpRequest.getParameter("scope"));
                List clientScopes = utilService.getScopes(authorService.getClient(request.getClientId()).getScopes());

                List temp = new ArrayList(requestScopes);
                Collections.copy(temp , requestScopes);
                temp.removeAll(clientScopes);

                if(temp.size() > 0){
                    log.error("invalid scope error in /approve");
                    System.out.println("httpRequest.getParameter(\"scope\") = " + httpRequest.getParameter("scope"));
                    System.out.println("authorService.getClient(request.getClientId()).getScopes() = " + authorService.getClient(request.getClientId()).getScopes());
                    attributes.addAttribute("error","invalid_scope");
                    return "redirect:" + request.getRedirectUri();
                }

                String code = RandomStringUtils.randomAlphanumeric(8);
                UserEntity user = authorService.getUser(httpRequest.getParameter("user"));
                authorService.saveCode(code, request, httpRequest.getParameter("scope"), user); // 인증된 사용자의 ID

                attributes.addAttribute("code", code);
                attributes.addAttribute("state", request.getState());
                return "redirect:" + request.getRedirectUri();
            } else {
                attributes.addAttribute("error", "unsupported_response_type");
                return "redirect:" + request.getRedirectUri();
            }

        }

        attributes.addAttribute("error", "access_denied");
        return "redirect:" + request.getRedirectUri();
    }

    /*
     * 토큰 엔드 포인트 :
     * 클라이언트 App이 보낸 요청의 유효성검사를 실시하고,
     *
     * 1. grant_type == 'authorization_code' 일 경우
     *       클라이언트 App에게 Access Token과 Refresh Token을 전달한다.
     *       클라이언트는 Access Token을 통해 Resource Server로 접근할 것이다. (인가서버는 알 필요가 없음.)
     *
     * 2. grant_type == 'refresh_token' 일 경우
     *       서버에 저장되어 있는 client_id 로 refresh token 을 조회한다.
     *       일치하는 refresh token을 발견한 경우, 새로운 access token 을 발급하여 전달한다.
     * */
    @PostMapping("/token")
    public ResponseEntity postToken(HttpServletRequest request, HttpServletResponse response) throws JOSEException {
        String auth = request.getHeader("authorization");
        String clientId = "";
        String clientSecret = "";
        if (auth != null && !auth.equals("")) {
            HashMap clientCredentials = utilService.decodeClientCredentials(auth);
            clientId = (String) clientCredentials.get("id");
            clientSecret = (String) clientCredentials.get("secret");
        }

        if (request.getParameter("client_id") != null) {
            if (!clientId.equals("")) {
                log.error("클라이언트가 여러번 인증 시도하고 있음.");
                // status 401 반환
                return new ResponseEntity(HttpStatus.UNAUTHORIZED);
            }

            clientId = request.getParameter("client_id");
            clientSecret = request.getParameter("client_secret");
        }

        Client client = authorService.getClient(clientId);

        if (client.getClientId().equals("")) {
            log.error("알 수 없는 클라이언트 " + clientId);
            return new ResponseEntity(HttpStatus.BAD_REQUEST);
        }

        if (!client.getClientSecret().equals(clientSecret)) {
            log.error("클라이언트 비밀키가 일치하지 않음.");
            return new ResponseEntity(HttpStatus.BAD_REQUEST);
        }

        if (request.getParameter("grant_type").equals("authorization_code")) {

            String key = request.getParameter("code");

            CodeEntity codeEntity = authorService.getCode(key);
            RequestEntity requestEntity = new RequestEntity(
                    codeEntity.getRequestId(),
                    codeEntity.getResponseType(),
                    codeEntity.getRedirectUri(),
                    codeEntity.getState(),
                    codeEntity.getClientId()
            );

            if (codeEntity != null) {
                authorService.removeCode(key);
                if (requestEntity.getClientId().equals(clientId)) {

                    String stringSharedSecret = "shared OAuth token secret!shared OAuth token secret!shared OAuth token secret!shared OAuth token secret!shared OAuth token secret!shared OAuth token secret!shared OAuth token secret!shared OAuth token secret!shared OAuth token secret!shared OAuth token secret!";
                    byte[] sharedSecret = stringSharedSecret.getBytes();

                    HashMap<String,Object> payload = new HashMap<>();
                    payload.put("iss","http://localhost:8091/");
                    payload.put("sub", clientId);
                    payload.put("aud","http://localhost:9002/");
                    payload.put("iat", LocalDateTime.now().toString());
                    payload.put("exp", LocalDateTime.now().plusMinutes(5).toString());
                    payload.put("iat", new Date().getTime());
                    payload.put("exp", new Date().getTime() + (1000 * 60 * 5));
                    payload.put("jti", RandomStringUtils.randomAlphanumeric(8));

                    // HS256을 이용한 대칭 시그니처
                    // TODO 시크릿의 최소 크기는 256비트임.
                    JWSSigner signer = new MACSigner(sharedSecret);

                    JWSObject jwsObject = new JWSObject(
                            new JWSHeader(JWSAlgorithm.HS256), new Payload(payload)
                    );

                    jwsObject.sign(signer);

                    // ID Token 발급
                    String serializedIdToken = "";
                    if(codeEntity.getScopes().contains("openid")){
                        serializedIdToken = authorService.generateSerializedIdToken(codeEntity);
                    }

                    String access_token = jwsObject.serialize();
                    String refresh_token = RandomStringUtils.randomAlphanumeric(32);

                    TokenResponseEntity tokenResponseEntity = new TokenResponseEntity(
                            clientId,
                            access_token,
                            refresh_token,
                            "Bearer",
                            codeEntity.getScopes(),
                            serializedIdToken
                    );

                    authorService.saveTokenResponse(tokenResponseEntity);
                    log.info("access token 발급 : " + access_token);
                    // Id Token log
                    log.info("ID token 발급 : "+ serializedIdToken);

                    TokenResponse tokenResponse = new TokenResponse(
                            tokenResponseEntity.getClientId(),
                            tokenResponseEntity.getAccessToken(),
                            tokenResponseEntity.getRefreshToken(),
                            tokenResponseEntity.getTokenType(),
                            tokenResponseEntity.getScopes(),
                            tokenResponseEntity.getSerializedIdToken()
                    );

                    return new ResponseEntity(tokenResponse, HttpStatus.OK);
                }
            }

        } else if (request.getParameter("grant_type").equals("refresh_token")) {

            TokenResponseEntity tokenResponseEntity = authorService.getTokenResponse(clientId);
            String refreshToken = tokenResponseEntity.getRefreshToken();

            if (refreshToken != null && refreshToken.equals(request.getParameter("refresh_token"))) {

                log.info("매칭되는 리프레시토큰을 발견하였음. " + request.getParameter("refresh_token"));

                if (!tokenResponseEntity.getClientId().equals(clientId)) { // 리프레시토큰과 매핑된 클라이언트 아이디가 전달받은 클라이언트 아이디와 불일치
                    authorService.removeTokenResponseByRefreshToken(refreshToken);
                    HashMap res = new HashMap();
                    res.put("error", "invalid_grant");
                    return new ResponseEntity(res, HttpStatus.BAD_REQUEST);
                }

                String access_token = RandomStringUtils.randomAlphanumeric(32);
                authorService.removeTokenResponse(tokenResponseEntity);

                TokenResponseEntity nextTokenResponseEntity = authorService.saveTokenResponse(new TokenResponseEntity(
                        clientId,
                        access_token,
                        refreshToken,
                        "Bearer", tokenResponseEntity.getScopes() , "TODO TAKE IDTOKEN"
                )); // TODO 리프레쉬토큰을 사용할 때에도 ID TOKEN을 재발급 해야하는가? 고려해야함.

                TokenResponse tokenResponse = new TokenResponse(
                        nextTokenResponseEntity.getClientId(),
                        nextTokenResponseEntity.getAccessToken(),
                        nextTokenResponseEntity.getRefreshToken(),
                        nextTokenResponseEntity.getTokenType() ,
                        nextTokenResponseEntity.getScopes(), ""
                ); // TODO 리프레쉬토큰을 사용할 때에도 ID TOKEN을 재발급 해야하는가? 고려해야함.

                return new ResponseEntity(tokenResponse, HttpStatus.OK);

            } else {
                log.error("매칭되는 리프레시토큰이 존재하지 않음");
                HashMap res = new HashMap();
                res.put("error", "invalid_grant");
                return new ResponseEntity(res, HttpStatus.BAD_REQUEST);
            }

        }

        return new ResponseEntity(HttpStatus.BAD_REQUEST);
    }

    /*
    * 토큰 인트로스펙션
    *
    * Resource 서버가 Authorization 서버로 토큰의 유효성 질의를 실시한다.
    *
    * header : {
    *   Authorizaiton : Basic {'resource server id : resource server secret'을 Base64로 encoding}
    * }
    * token = {Resource 서버가 Client로부터 전달 받은 Access Token}
    *
    * Authorization 서버에 Resource 서버의 id , secret 이 저장되어 있음을 전제한다.
    *
    * */
    @PostMapping("/introspect")
    public ResponseEntity postIntrospect(HttpServletRequest request) {

        String auth = request.getHeader("authorization");
        HashMap<String, String> clientCredentials = utilService.decodeClientCredentials(auth);
        String id = clientCredentials.get("id");
        String secret = clientCredentials.get("secret");

        ProtectedResourceEntity protectedResourceEntity = authorService.getProtectedResource(id);

        if(protectedResourceEntity.getId() == null){
            return new ResponseEntity(HttpStatus.UNAUTHORIZED);
        }

        if(!protectedResourceEntity.getResourceSecret().equals(secret)){
            return new ResponseEntity(HttpStatus.UNAUTHORIZED);
        }

        String inToken = request.getParameter("token");
        TokenResponseEntity tokenResponse = authorService.getTokenResponseByAccessToken(inToken);
        HashMap<String,Object> introspectionResponse = new HashMap<>();

        if(tokenResponse.getClientId() != null){
            introspectionResponse.put("active", true);
            introspectionResponse.put("iss","http://localhost:8091/");
            introspectionResponse.put("sub", tokenResponse.getClientId());
            introspectionResponse.put("aud","http://localhost:9002/");
            introspectionResponse.put("scope", tokenResponse.getScopes());
            introspectionResponse.put("client_id",tokenResponse.getClientId());

            return new ResponseEntity(introspectionResponse, HttpStatus.OK);
        } else {
            introspectionResponse.put("active", false);
            return new ResponseEntity(introspectionResponse,HttpStatus.OK);
        }

    }

    /*
    * 리소스 서버가 Auth 서버에게 디코딩 된 Serialized Id Token의 Payload를 요청한다.
    *
    * */

    @PostMapping("/idToken")
    public ResponseEntity postIdToken(HttpServletRequest request) throws JsonProcessingException {

        String auth = request.getHeader("authorization");
        HashMap<String, String> clientCredentials = utilService.decodeClientCredentials(auth);
        String id = clientCredentials.get("id");
        String secret = clientCredentials.get("secret");

        ProtectedResourceEntity protectedResourceEntity = authorService.getProtectedResource(id);

        if(protectedResourceEntity.getId() == null){
            return new ResponseEntity(HttpStatus.UNAUTHORIZED);
        }

        if(!protectedResourceEntity.getResourceSecret().equals(secret)){
            return new ResponseEntity(HttpStatus.UNAUTHORIZED);
        }

        String inToken = request.getParameter("token");
        TokenResponseEntity tokenResponse = authorService.getTokenResponseByAccessToken(inToken);
        String serializedIdToken = tokenResponse.getSerializedIdToken();

        HashMap<String, String> response = utilService.getPayload(serializedIdToken);

        return new ResponseEntity(response, HttpStatus.OK);
    }

    @PostMapping("/revoke")
    public ResponseEntity postRevoke(HttpServletRequest request) {
        String auth = request.getHeader("authorization");

        HashMap<String, String> clientCredentials = utilService.decodeClientCredentials(auth);
        String clientId = clientCredentials.get("id");
        String clientSecret = clientCredentials.get("secret");

        if(request.getParameter("client_id") != null){
            if(clientId != null){
                return new ResponseEntity(
                        new HashMap<>().put("error", "invalid_client"),
                        HttpStatus.UNAUTHORIZED);
            }

            clientId = request.getParameter("client_id");
            clientSecret = request.getParameter("client_secret");
        }

        Client client = authorService.getClient(clientId);

        if(client.getClientId().equals("")){
            return new ResponseEntity(
                    new HashMap<>().put("error", "invalid_client"),
                    HttpStatus.UNAUTHORIZED);
        }

        if(!client.getClientSecret().equals(clientSecret)){
            return new ResponseEntity(
                    new HashMap<>().put("error", "invalid_client"),
                    HttpStatus.UNAUTHORIZED);
        }

        String inToken = request.getParameter("token");
        TokenResponseEntity tokenResponseByAccessToken = authorService.getTokenResponseByAccessToken(inToken);
        authorService.removeTokenResponse(tokenResponseByAccessToken);
        return new ResponseEntity(HttpStatus.NO_CONTENT);
    }


}
