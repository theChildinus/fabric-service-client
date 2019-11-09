import com.alibaba.fastjson.JSONObject;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.NetworkConfig;
import org.hyperledger.fabric.sdk.helper.Utils;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric_ca.sdk.Attribute;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.w3c.dom.Attr;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;

public class CAClient {
    private static final String adminUsername = "admin";
    private static final String adminPassword = "adminpw";
    private static final Path storePath = Paths.get("./card");
    private NetworkConfig.OrgInfo orgInfo;
    private NetworkConfig.CAInfo caInfo;

    public CAClient(NetworkConfig.OrgInfo orgInfo) {
        this.orgInfo = orgInfo;
        this.caInfo = orgInfo.getCertificateAuthorities().get(0);
    }

    private SampleUser enrollAdmin() throws Exception {
        File file = new File(storePath + "/admin.card");
        if (!file.exists()) {
            SampleUser sampleUser = new SampleUser();
            HFCAClient caClient = HFCAClient.createNewInstance(caInfo);
            caClient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

            Enrollment enrollment = caClient.enroll(adminUsername, adminPassword);
            sampleUser.setName(adminUsername);
            sampleUser.setPrivateKey(UserUtils.getPEMString(enrollment.getKey()));
            sampleUser.setSignedCert(enrollment.getCert());
            FileWriter fileWriter = new FileWriter(file);
            String encode = Base64.encode(JSONObject.toJSONString(sampleUser).getBytes());
            fileWriter.write(encode);
            fileWriter.close();
            return sampleUser;
        }
        SampleUser fabricAdmin = UserUtils.unSerializeUser(file);
        fabricAdmin.setMspId(orgInfo.getMspId());
        return fabricAdmin;
    }

    public SampleUser registerUser(String username, ArrayList<Attribute> attList) throws Exception {
        SampleUser fabricAdmin = enrollAdmin();
        File cardfile = new File(storePath + "/" + username + "/" + username + ".card");
        if (!cardfile.exists()) {
            HFCAClient caClient = HFCAClient.createNewInstance(caInfo);
            caClient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
            RegistrationRequest rr = new RegistrationRequest(username);
            rr.setType("user");
            if (!attList.isEmpty()) {
                for (Attribute attribute : attList) {
                    rr.addAttribute(attribute);
                }
            }
            String enrollmentSecret = caClient.register(rr, fabricAdmin);
            SampleUser newUser = new SampleUser();
            newUser.setName(username);
            newUser.setEnrollmentSecret(enrollmentSecret);
            return newUser;
        }
        SampleUser fabricUser = UserUtils.unSerializeUser(cardfile);
        return fabricUser;
    }

    public void enrollUser(SampleUser user, ArrayList<Attribute> attList) throws Exception {
        String username = user.getName();
        File cardfile = new File(storePath + "/" + username + "/" + username + ".card");
        File certfile = new File(storePath + "/" + username + "/" + username + ".crt");
        File keyfile = new File(storePath + "/"+ username + "/" + username + ".pem");
        HFCAClient caClient = HFCAClient.createNewInstance(caInfo);
        caClient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
        if (!cardfile.exists()) {
            if (!cardfile.getParentFile().mkdirs()) {
                System.out.println("Create Dir Failed");
            }
        }
        Enrollment enrollment = null;
        if (!attList.isEmpty()) {
            EnrollmentRequest req = new EnrollmentRequest();
            for (Attribute attribute : attList) {
                req.addAttrReq(attribute.getName()).setOptional(true);
            }
            enrollment = caClient.enroll(username, user.getEnrollmentSecret(), req);
        } else {
            enrollment = caClient.enroll(username, user.getEnrollmentSecret());
        }
        String signedCert = enrollment.getCert();
        user.setPrivateKey(UserUtils.getPEMString(enrollment.getKey()));
        user.setSignedCert(signedCert);
        FileWriter cardWriter = new FileWriter(cardfile);
        FileWriter certWriter = new FileWriter(certfile);
        FileWriter keyWriter = new FileWriter(keyfile);
        String encode = Base64.encode(JSONObject.toJSONString(user).getBytes());
        cardWriter.write(encode);
        certWriter.write(user.getSignedCert());
        keyWriter.write(user.getPrivateKey());
        cardWriter.close();
        certWriter.close();
        keyWriter.close();
    }

    public String revokeUser (SampleUser user) throws Exception {
        String username = user.getName();
        HFCAClient caClient = HFCAClient.createNewInstance(caInfo);
        caClient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
        String revoke = caClient.revoke(user, user.getEnrollment(), "Revoke User " + user.getName(), true);
        File certfile = new File(storePath + "/" + username + "/" + username + ".crt");
        File keyfile = new File(storePath + "/" + username + "/" + username + ".pem");
        Utils.deleteFileOrDirectory(certfile);
        Utils.deleteFileOrDirectory(keyfile);
        return revoke;
    }



    public static void main(String[] args) throws Exception {
        Path connectionFilePath = Paths.get("./", "connection.json");
        ConnectionProfile connectionProfile = new ConnectionProfile(connectionFilePath.toFile());
        CAClient caClient = new CAClient(connectionProfile.getNetworkConfig().getClientOrganization());
        ArrayList<Attribute> attList = new ArrayList<Attribute>();
        String username = "test9";
        System.out.println("===== 在 Fabric CA 注册用户 =====");
        SampleUser user = caClient.registerUser(username, attList);
        System.out.println("===== 在 Fabric CA 登录用户，并创建用户私钥和证书 =====");
        caClient.enrollUser(user, attList);
        System.out.println("===== 在 Fabric CA 注销用户，并删除用户私钥和证书 =====");
        File cardFile = new File("./card/" + username + "/" + username + ".card");
        SampleUser ruser = UserUtils.unSerializeUser(cardFile);
        String revoke = caClient.revokeUser(ruser);
        System.out.println("revoke: " + revoke);
    }
}