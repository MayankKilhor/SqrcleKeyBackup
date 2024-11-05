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
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import payload.request.KeyUploadRequest;
import payload.request.KeyUploadRequestParser;

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
           String userId =input.getHeaders().get("userID");
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
               return response
                       .withBody("Unable to Fetch User Details!")
                       .withStatusCode(400);
           }
           PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
           if (!passwordEncoder.matches(keyUploadRequest.getPassword(), user.getPassword())) {
               return response
                       .withBody("Authentication failed!")
                       .withStatusCode(401);
           }
           if(userId == null || userId.length()!=16){
               return response
                       .withBody("UserId Invalid!")
                       .withStatusCode(400);
           }
           if(keyUploadRequest.getPrivateKey() == null){
               return response
                       .withBody("PrivateKey cannot be null!")
                       .withStatusCode(400);
           }
           String encryptionKey = keyUploadRequest.getPassword();
           SecurityUtil securityUtil = new SecurityUtil();
           SecretKey secretKey = securityUtil.generateKey(encryptionKey);

           if (circles == null) {
               return response
                       .withBody("Circles list cannot be null")
                       .withStatusCode(400);

           }
           for (Circle circle : circles) {
               if (circle == null) {
                   return response
                           .withBody("Circle cannot be null")
                           .withStatusCode(400);
               }
               if (circle.getCircleId() == null) {
                   return response
                           .withBody("Circle ID cannot be null")
                           .withStatusCode(400);
               }
               if (circle.getCircleHash() == null) {
                   return response
                           .withBody("Circle hash cannot be null")
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
               return response
                       .withBody("Incorrect circle details or userID")
                       .withStatusCode(400);
           }

           if(keyUploadRequest.getCircles().get(0).getCircleId() == null ||keyUploadRequest.getCircles().get(0).getCircleHash()== null){
               return response
                       .withBody("Circle details Invalid!")
                       .withStatusCode(400);
           }
           KeyBackup keyBackup = new KeyBackup(keyUploadRequest.getPrivateKey(),keyUploadRequest.getCircles(),userId);
           String json = objectMapper.writeValueAsString(keyBackup);
           String key = username+"/keys.json";
           if(keyUploadRequest.getEncrypted()){
               byte[] encryptedData = securityUtil.encrypt(json,secretKey);
//               Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//               byte[] keyBytes = encryptionKey.getBytes();
//               SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
//               cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
//               byte[] encryptedData = cipher.doFinal(json.getBytes());
               try (FileOutputStream outputStream = new FileOutputStream(filePath)) {
                   outputStream.write(encryptedData);
               } catch (IOException e) {
                   return response
                           .withBody("body+" + input.getBody() + "\n" + e.getMessage())
                           .withStatusCode(500);

               }
           }else{
               try (FileWriter fileWriter = new FileWriter(filePath)) {
                   fileWriter.write(json);
               } catch (IOException e) {
                   return response
                           .withBody("body+"+input.getBody()+"\n"+e.getMessage())
                           .withStatusCode(500);

               }
           }

           File file = new File(filePath);
           s3Client.putObject(new PutObjectRequest(bucketName, key,file));
           Map<String, Object> fieldsToUpdate = new HashMap<>();
           fieldsToUpdate.put("keysBackup", true);
           fieldsToUpdate.put("backupEncryption", keyUploadRequest.getEncrypted());
           databaseUtil.updateFields(username, fieldsToUpdate);
           return response
                   .withBody("Data is stored in :-"+key)
                   .withStatusCode(200);

       }catch(Exception e){
           APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
           return response
                   .withBody("body+"+input.getBody()+"\n"+e.getMessage())
                   .withStatusCode(500);
       }
    }


}
