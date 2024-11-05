package Models;

import java.util.List;

public class KeyBackup {

    private String privateKey;
    private List<Circle> circles;
    private String userId;

    public KeyBackup(String privateKey, List<Circle> circles, String userId) {
        this.privateKey = privateKey;
        this.circles = circles;
        this.userId = userId;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }


    public List<Circle> getCircles() {
        return circles;
    }

    public void setCircles(List<Circle> circles) {
        this.circles = circles;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }
}
