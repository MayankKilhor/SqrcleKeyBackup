package Upload;

import java.io.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import Models.Circle;
import Models.KeyBackup;
import Models.User;
import Utils.DatabaseUtil;
import Utils.SecurityUtil;
import Utils.ValidatorUtil;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import payload.request.KeyUploadRequest;
import payload.request.KeyUploadRequestParser;
import payload.response.ApiResponse;

import javax.crypto.SecretKey;

/**
 * Handler for requests to Lambda function.
 */
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
           String userId =input.getHeaders().get("userId");
           String filePath = "/tmp/keys.json";
           APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
           String requestBody = input.getBody();
           KeyUploadRequest keyUploadRequest = KeyUploadRequestParser.parseRequest(requestBody);
           ObjectMapper objectMapper = new ObjectMapper();
           User user = new User();
           DatabaseUtil databaseUtil = new DatabaseUtil();
           user = databaseUtil.findByUserName(username);
           List<Circle> circles =  keyUploadRequest.getCircles();
           if(user == null){
               ApiResponse apiResponse = new ApiResponse(false,"Unable to fetch User details");
               apiResponse.addDetail("error","Unable to fetch User details from the database!");
               apiResponse.addDetail("username",username);
               String jsonResponse = objectMapper.writeValueAsString(apiResponse);
               return response
                       .withBody(jsonResponse)
                       .withStatusCode(400);
           }
           PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
           if (!passwordEncoder.matches(keyUploadRequest.getPassword(), user.getPassword())) {
               ApiResponse apiResponse = new ApiResponse(false,"Authentication failed, Password is incorrect");
               apiResponse.addDetail("error","Authentication failed, Password is incorrect!");
               apiResponse.addDetail("username",username);
               String jsonResponse = objectMapper.writeValueAsString(apiResponse);
               return response
                       .withBody(jsonResponse)
                       .withStatusCode(401);
           }
           if(userId == null || userId.length()!=16){
               ApiResponse apiResponse = new ApiResponse(false,"UserId format is Invalid!");
               apiResponse.addDetail("error","UserId format is Invalid!");
               String jsonResponse = objectMapper.writeValueAsString(apiResponse);
               return response
                       .withBody(jsonResponse)
                       .withStatusCode(400);
           }
           if(keyUploadRequest.getPrivateKey() == null){
               ApiResponse apiResponse = new ApiResponse(false,"Private Key can't be null");
               apiResponse.addDetail("error","Private Key can't be null!");
               String jsonResponse = objectMapper.writeValueAsString(apiResponse);
               return response
                       .withBody(jsonResponse)
                       .withStatusCode(400);
           }
           String encryptionKey = keyUploadRequest.getPassword();
           SecurityUtil securityUtil = new SecurityUtil();
           SecretKey secretKey = securityUtil.generateKey(encryptionKey);

           if (circles == null) {
               ApiResponse apiResponse = new ApiResponse(false,"Circle List can't be null");
               apiResponse.addDetail("error","Circle List can't be null!");
               String jsonResponse = objectMapper.writeValueAsString(apiResponse);
               return response
                       .withBody(jsonResponse)
                       .withStatusCode(400);

           }
           for (Circle circle : circles) {
               if (circle == null) {
                   ApiResponse apiResponse = new ApiResponse(false,"Circle can't be null");
                   apiResponse.addDetail("error","Circle can't be null!");
                   String jsonResponse = objectMapper.writeValueAsString(apiResponse);
                   return response
                           .withBody(jsonResponse)
                           .withStatusCode(400);
               }
               if (circle.getCircleId() == null) {
                   ApiResponse apiResponse = new ApiResponse(false,"Circle ID can't be null");
                   apiResponse.addDetail("error","Circle ID can't be null!");
                   String jsonResponse = objectMapper.writeValueAsString(apiResponse);
                   return response
                           .withBody(jsonResponse)
                           .withStatusCode(400);
               }
               if (circle.getCircleHash() == null) {
                   ApiResponse apiResponse = new ApiResponse(false,"Circle hash can't be null");
                   apiResponse.addDetail("error","Circle hash can't be null!");
                   String jsonResponse = objectMapper.writeValueAsString(apiResponse);
                   return response
                           .withBody(jsonResponse)
                           .withStatusCode(400);
               }
//               if(circle.getCoi() == null){
//                   return response
//                           .withBody("Circle COI cannot be null")
//                           .withStatusCode(400);
//               }
           }
           Boolean validDetails = ValidatorUtil.validCircleandUserID(userId,circles);
           if(!validDetails){
               ApiResponse apiResponse = new ApiResponse(false,"Incorrect circle details or UserId");
               apiResponse.addDetail("error","Incorrect circle details or UserId!");
               String jsonResponse = objectMapper.writeValueAsString(apiResponse);
               return response
                       .withBody(jsonResponse)
                       .withStatusCode(400);
           }

           if(keyUploadRequest.getCircles().get(0).getCircleId() == null ||keyUploadRequest.getCircles().get(0).getCircleHash()== null){
               ApiResponse apiResponse = new ApiResponse(false,"Circle details Invalid");
               apiResponse.addDetail("error","Circle details Invalid!");
               String jsonResponse = objectMapper.writeValueAsString(apiResponse);
               return response
                       .withBody(jsonResponse)
                       .withStatusCode(400);
           }
           KeyBackup keyBackup = new KeyBackup(keyUploadRequest.getPrivateKey(),keyUploadRequest.getCircles(),userId);
           String json = objectMapper.writeValueAsString(keyBackup);
           String key = username+"/keys.json";
           if(keyUploadRequest.getEncrypted()){
               byte[] encryptedData = securityUtil.encrypt(json,secretKey);
//
               try (FileOutputStream outputStream = new FileOutputStream(filePath)) {
                   outputStream.write(encryptedData);
               } catch (IOException e) {
                   ApiResponse apiResponse = new ApiResponse(false,"Unable to Upload Key");
                   apiResponse.addDetail("error",e.getMessage());
                   apiResponse.addDetail("body",input.getBody());
                   String jsonResponse = null;
                   try {
                       jsonResponse = objectMapper.writeValueAsString(apiResponse);
                   } catch (JsonProcessingException ex) {
                       throw new RuntimeException(ex);
                   }
                   return response
                           .withBody(jsonResponse)
                           .withStatusCode(500);
               }
           }else{
               try (FileWriter fileWriter = new FileWriter(filePath)) {
                   fileWriter.write(json);
               } catch (IOException e) {
                   ApiResponse apiResponse = new ApiResponse(false,"Unable to backup Key");
                   apiResponse.addDetail("error",e.getMessage());
                   apiResponse.addDetail("body",input.getBody());
                   String jsonResponse = null;
                   try {
                       jsonResponse = objectMapper.writeValueAsString(apiResponse);
                   } catch (JsonProcessingException ex) {
                       throw new RuntimeException(ex);
                   }
                   return response
                           .withBody(jsonResponse)
                           .withStatusCode(500);
               }
           }

           File file = new File(filePath);
           s3Client.putObject(new PutObjectRequest(bucketName, key,file));
           Map<String, Object> fieldsToUpdate = new HashMap<>();
           fieldsToUpdate.put("keysBackup", true);
           fieldsToUpdate.put("backupEncryption", keyUploadRequest.getEncrypted());
           databaseUtil.updateFields(username, fieldsToUpdate);
           ApiResponse apiResponse = new ApiResponse(true,"Successfully backedup the keys");
           apiResponse.addDetail("keyPath",key);
           String jsonResponse = objectMapper.writeValueAsString(apiResponse);
           return response
                   .withBody(jsonResponse)
                   .withStatusCode(200);

       }catch(Exception e){
           APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
           ApiResponse apiResponse = new ApiResponse(false,"Unable to backup Key");
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
