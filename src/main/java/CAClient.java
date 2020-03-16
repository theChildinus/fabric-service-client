import com.alibaba.fastjson.JSONObject;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import org.bouncycastle.jcajce.provider.symmetric.VMPC;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.NetworkConfig;
import org.hyperledger.fabric.sdk.helper.Utils;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric_ca.sdk.*;
import org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException;
import org.w3c.dom.Attr;
import proto.*;

import java.io.*;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

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

    public X509Certificate getCertificate(String username) throws Exception {
        HFCAClient caClient = HFCAClient.createNewInstance(caInfo);
        caClient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
        SampleUser fabricAdmin = enrollAdmin();
        HFCACertificateRequest certReq = caClient.newHFCACertificateRequest();
        String md5Str = getMd5Str(username);
        certReq.setEnrollmentID(md5Str);
        HFCACertificateResponse certResp = caClient.getHFCACertificates(fabricAdmin, certReq);
        ArrayList<HFCACredential> certs = (ArrayList<HFCACredential>)certResp.getCerts();
        System.out.println("certs length: " + certs.size());
        HFCAX509Certificate cert = (HFCAX509Certificate)certs.get(certs.size() - 1);
        return cert.getX509();
    }

    public boolean verifyCert(String username, InputStream usercert) throws Exception {
        X509Certificate certFromCA = getCertificate(username);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate certFromU = (X509Certificate)cf.generateCertificate(usercert);
        certFromU.checkValidity();
        if (certFromCA.getSerialNumber().equals(certFromU.getSerialNumber())
            && Arrays.equals(certFromCA.getSignature(), certFromU.getSignature())) {
            return true;
        } else {
            return false;
        }
    }

    public int registerIdentity(RegisterReq req) throws Exception {
        SampleUser fabricAdmin = enrollAdmin();
        String username = req.getName();
        File cardfile = new File(storePath + "/" + username + "/" + username + ".card");
        if (!cardfile.exists()) {
            if (!cardfile.getParentFile().mkdirs()) {
                System.out.println("Create Dir Failed");
            }
            HFCAClient caClient = HFCAClient.createNewInstance(caInfo);
            caClient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
            String md5Str = getMd5Str(username);
            RegistrationRequest rr = new RegistrationRequest(md5Str);
            rr.setType(req.getType());
            rr.setAffiliation(req.getAffiliation());
            rr.setSecret(req.getSecret());
            if (!req.getAttrs().isEmpty()) {
                String[] attrs = req.getAttrs().split(",");
                for (String attr : attrs) {
                    String[] kv = attr.split("=");
                    rr.addAttribute(new Attribute(kv[0], kv[1]));
                }
            }
            String enrollmentSecret = caClient.register(rr, fabricAdmin);
            SampleUser newUser = new SampleUser();
            newUser.setName(md5Str);
            newUser.setEnrollmentSecret(enrollmentSecret);
            FileWriter cardWriter = new FileWriter(cardfile);
            String encode = Base64.encode(JSONObject.toJSONString(newUser).getBytes());
            cardWriter.write(encode);
            cardWriter.close();
            return 0;
        }
        return -1;
    }

    public int enrollIdentity(EnrollReq req) throws Exception {
        String username = req.getName();
        File cardfile = new File(storePath + "/" + username + "/" + username + ".card");
        File certfile = new File(storePath + "/" + username + "/" + username + ".crt");
        File keyfile = new File(storePath + "/" + username + "/" + username + ".pem");
        SampleUser user = UserUtils.unSerializeUser(cardfile);
        HFCAClient caClient = HFCAClient.createNewInstance(caInfo);
        caClient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
        if (!cardfile.exists()) {
            if (!cardfile.getParentFile().mkdirs()) {
                System.out.println("Create Dir Failed");
            }
        }
        Enrollment enrollment = null;
        if (!req.getAttrs().isEmpty()) {
            EnrollmentRequest er = new EnrollmentRequest();
//            for (Attribute attribute : attList) {
//                er.addAttrReq(attribute.getName()).setOptional(true);
//            }
            enrollment = caClient.enroll(user.getName(), user.getEnrollmentSecret(), er);
        } else {
            enrollment = caClient.enroll(user.getName(), user.getEnrollmentSecret());
        }
        String signedCert = enrollment.getCert();
        user.setPrivateKey(UserUtils.getPEMString(enrollment.getKey()));
        user.setSignedCert(signedCert);
        user.setRevoked(false);
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
        return 0;
    }

    public String revokeIdentity(RevokeReq req) throws Exception {
        String username = req.getName();
        HFCAClient caClient = HFCAClient.createNewInstance(caInfo);
        caClient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
        File cardfile = new File(storePath + "/" + username + "/" + username + ".card");
        File certfile = new File(storePath + "/" + username + "/" + username + ".crt");
        File keyfile = new File(storePath + "/" + username + "/" + username + ".pem");
        SampleUser user = UserUtils.unSerializeUser(cardfile);
        String revoke = caClient.revoke(user, user.getEnrollment(), "Revoke Identity " + user.getName(), true);
        user.setRevoked(true);
        FileWriter cardWriter = new FileWriter(cardfile);
        String encode = Base64.encode(JSONObject.toJSONString(user).getBytes());
        cardWriter.write(encode);
        cardWriter.close();
        if (certfile.exists() && keyfile.exists()) {
            Utils.deleteFileOrDirectory(certfile);
            Utils.deleteFileOrDirectory(keyfile);
        }
        return revoke;
    }

    private String getMd5Str(String str) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(str.getBytes());
        String md5sum = new BigInteger(1, md.digest()).toString(16);
        System.out.println("username: " + str + ", md5sum: " + md5sum);
        return md5sum;
    }

    public static void main(String[] args) throws Exception {
        Path connectionFilePath = Paths.get("./", "connection.json");
        ConnectionProfile connectionProfile = new ConnectionProfile(connectionFilePath.toFile());
        CAClient caClient = new CAClient(connectionProfile.getNetworkConfig().getClientOrganization());
        String username = "赵孔阳";
        File cardFile = new File(storePath + "/" + username + "/" + username + ".card");
        File certFile = new File(storePath + "/" + username + "/" + username + ".crt");

        System.out.println("===== 在 Fabric CA 注册用户 =====");
        RegisterReq rq = RegisterReq.newBuilder().setName(username).build();
        caClient.registerIdentity(rq);

        System.out.println("===== 在 Fabric CA 登录用户，并创建用户私钥和证书 =====");
        EnrollReq eq = EnrollReq.newBuilder().setName(username).build();
        caClient.enrollIdentity(eq);

        System.out.println("===== 证书验证 =====");
        FileInputStream in = new FileInputStream(certFile);
        System.out.println(caClient.verifyCert(username, in));
        in.close();

        System.out.println("===== 在 Fabric CA 注销用户，并删除用户私钥和证书 =====");
        RevokeReq rrq = RevokeReq.newBuilder().setName(username).build();
        String revoke = caClient.revokeIdentity(rrq);
        System.out.println("revoke: " + revoke);
    }
}
