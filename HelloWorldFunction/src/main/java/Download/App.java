package Download;

import Models.User;
import Utils.DatabaseUtil;
import Utils.SecurityUtil;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import payload.request.KeyDownloadRequest;
import payload.request.KeyDownloadRequestParser;
import payload.response.ApiResponse;

import javax.crypto.SecretKey;
import java.io.*;
import java.util.Map;

public class App implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final String bucketName = System.getenv("bucketName");
    private final String region = System.getenv("regionName");
    private final AmazonS3 s3Client = AmazonS3ClientBuilder
            .standard()
            .withRegion(region)
            .build();


    public APIGatewayProxyResponseEvent handleRequest(final APIGatewayProxyRequestEvent input, final Context context) {
        try {
            String username =input.getHeaders().get("username");
            String objectKey = username+"/keys.json";
            APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();

            String requestBody = input.getBody();
            KeyDownloadRequest keyDownloadRequest = KeyDownloadRequestParser.parseRequest(requestBody);
            User user = new User();
            DatabaseUtil databaseUtil = new DatabaseUtil();
            user = databaseUtil.findByUserName(username);
            if(user == null){
                ApiResponse apiResponse = new ApiResponse(false,"Unable to fetch User details");
                apiResponse.addDetail("error","Unable to fetch User details from the database!");
                apiResponse.addDetail("username",username);
                ObjectMapper objectMapper = new ObjectMapper();
                String jsonResponse = objectMapper.writeValueAsString(apiResponse);
                return response
                        .withBody(jsonResponse)
                        .withStatusCode(400);
            }
            if(!user.getKeysBackup()){
                ApiResponse apiResponse = new ApiResponse(false,"User Backup doesn't exist");
                apiResponse.addDetail("error","User Backup doesn't exist!");
                apiResponse.addDetail("username",username);
                ObjectMapper objectMapper = new ObjectMapper();
                String jsonResponse = objectMapper.writeValueAsString(apiResponse);
                return response
                        .withBody(jsonResponse)
                        .withStatusCode(400);
            }
            PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
            if (!passwordEncoder.matches(keyDownloadRequest.getPassword(), user.getPassword())) {
                ApiResponse apiResponse = new ApiResponse(false,"Authentication failed, Password is incorrect");
                apiResponse.addDetail("error","Authentication failed, Password is incorrect!");
                apiResponse.addDetail("username",username);
                ObjectMapper objectMapper = new ObjectMapper();
                String jsonResponse = objectMapper.writeValueAsString(apiResponse);
                return response
                        .withBody(jsonResponse)
                        .withStatusCode(401);
            }
            String decryptionKey = keyDownloadRequest.getPassword();
            Boolean Encrypted = user.getBackupEncryption();

            S3Object s3Object = s3Client.getObject(new GetObjectRequest(bucketName, objectKey));
            String json="";
            if(Encrypted){
                byte[] encryptedData = s3Object.getObjectContent().readAllBytes();
                SecurityUtil securityUtil = new SecurityUtil();
                SecretKey secretKey = securityUtil.generateKey(decryptionKey);
                json = securityUtil.decrypt(encryptedData,secretKey);

            }else{

                BufferedReader reader = new BufferedReader(new InputStreamReader(s3Object.getObjectContent()));
                StringBuilder content = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    content.append(line);
                }

                reader.close();
                json=content.toString();
            }


            ObjectMapper objectMapper = new ObjectMapper();
            ApiResponse apiResponse = new ApiResponse(false,"Successfully downloaded key");
            Map<String, Object> keysMap = objectMapper.readValue(json, Map.class);
            apiResponse.addDetail("keys",keysMap);


            String jsonResponse = objectMapper.writeValueAsString(apiResponse);
            return response
                    .withBody(jsonResponse)
                    .withStatusCode(200);

        } catch (IOException e) {
            APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
            ApiResponse apiResponse = new ApiResponse(false,"Unable to download Key");
            apiResponse.addDetail("error",e.getMessage());
            apiResponse.addDetail("body",input.getBody());
            ObjectMapper objectMapper = new ObjectMapper();
            String jsonResponse = null;
            try {
                jsonResponse = objectMapper.writeValueAsString(apiResponse);
            } catch (JsonProcessingException ex) {
                throw new RuntimeException(ex);
            }
            return response
                    .withBody(jsonResponse)
                    .withStatusCode(500);

        }catch (Exception e){
            APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
            ApiResponse apiResponse = new ApiResponse(false,"Unable to download Key");
            apiResponse.addDetail("error",e.getMessage());
            apiResponse.addDetail("body",input.getBody());
            ObjectMapper objectMapper = new ObjectMapper();
            String jsonResponse = null;
            try {
                jsonResponse = objectMapper.writeValueAsString(apiResponse);
            } catch (JsonProcessingException ex) {
                jsonResponse = "{\"error\":\""+e.getMessage()+"\"}";
            }
            return response
                    .withBody(jsonResponse)
                    .withStatusCode(500);
        }
    }

}

