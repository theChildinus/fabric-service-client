import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.stub.StreamObserver;
import org.apache.log4j.BasicConfigurator;
import org.hyperledger.fabric_ca.sdk.Attribute;
import proto.*;

import java.io.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.logging.Logger;

public class FabricService {
    private static final Logger logger = Logger.getLogger(FabricService.class.getName());
    private Server server;

    private void start() throws IOException {
        int port = 50051;
        server = ServerBuilder.forPort(port)
                .addService(new FabricServiceImpl())
                .build()
                .start();
        logger.info("Server started, listening on " + port);
        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                // Use stderr here since the logger may have been reset by its JVM shutdown hook.
                System.err.println("*** shutting down gRPC server since JVM is shutting down");
                FabricService.this.stop();
                System.err.println("*** server shut down");
            }
        });
    }

    private void stop() {
        if (server != null) {
            server.shutdown();
        }
    }

    private void blockUntilShutdown() throws InterruptedException {
        if (server != null) {
            server.awaitTermination();
        }
    }

    public static void main(String[] args) throws IOException, InterruptedException {
        final FabricService server = new FabricService();
        server.start();
        server.blockUntilShutdown();
    }

    static class FabricServiceImpl extends FabricServiceGrpc.FabricServiceImplBase {
        @Override
        public void register(RegisterReq req, StreamObserver<RegisterResp> responseObserver) {
            logger.info("[Register] Received UserName:" + req.getUsername());
            RegisterResp resp;
            try {
                registerUser(req.getUsername());
                logger.info("[Register] "+ req.getUsername() + " Register Success");
                resp = RegisterResp.newBuilder().setCode(0).build();

            } catch (Exception e) {
                e.printStackTrace();
                logger.info("[Register] "+ req.getUsername() + " Register Failed");
                resp = RegisterResp.newBuilder().setCode(-1).build();
            }
            responseObserver.onNext(resp);
            responseObserver.onCompleted();
        }

        @Override
        public void download(DownloadReq req, StreamObserver<DownloadResp> responseObserver) {
            logger.info("[Download] Received UserName:" + req.getUsername());
            String userName = req.getUsername();
            StringBuilder sb = new StringBuilder();
            File file = new File("./card/" + userName + "/" + userName + ".crt");
            char[] buf = new char[1024];
            try {
                FileReader certReader = new FileReader(file);
                int num;
                while ((num = certReader.read(buf)) != -1) {
                    sb.append(buf, 0, num);
                }
                certReader.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
            DownloadResp resp;
            try {
                logger.info("[Download] " + req.getUsername() + " Cert Download Success");
                resp = DownloadResp.newBuilder().setCert(sb.toString()).build();
            } catch (Exception e) {
                e.printStackTrace();
                logger.info("[Download] " + req.getUsername() + " Cert Download Failed");
                resp = DownloadResp.newBuilder().setCert("").build();
            }
            responseObserver.onNext(resp);
            responseObserver.onCompleted();
        }

        @Override
        public void login(LoginReq req, StreamObserver<LoginResp> responseObserver) {
            logger.info("[Login] Received UserName:" + req.getUsername());
            LoginResp resp;
            try {
                boolean res = loginUserVerify(req.getUsername(), Base64.decode(req.getUsersign()), String.valueOf(req.getUserrand()));
                if (res) {
                    logger.info("[Login]" + req.getUsername() + " Login Success");
                    resp = LoginResp.newBuilder().setCode(0).build();
                } else {
                    logger.info("[Login]" + req.getUsername() + " Login Failed");
                    resp = LoginResp.newBuilder().setCode(-1).build();
                }

            } catch (Exception e) {
                e.printStackTrace();
                logger.info("[Login]" + req.getUsername() + " Login Failed");
                resp = LoginResp.newBuilder().setCode(-1).build();
            }
            responseObserver.onNext(resp);
            responseObserver.onCompleted();
        }

        @Override
        public void revoke(RevokeReq req, StreamObserver<RevokeResp> responseObserver) {
            logger.info("[Revoke] Received UserName:" + req.getUsername());
            RevokeResp resp;
            try {
                revokeUser(req.getUsername());
                logger.info("[Revoke]" + req.getUsername() + " Revoke Success");
                resp = RevokeResp.newBuilder().setCode(0).build();
            } catch (Exception e) {
                e.printStackTrace();
                logger.info("[Revoke]" + req.getUsername() + " Revoke Failed");
                resp = RevokeResp.newBuilder().setCode(-1).build();
            }
            responseObserver.onNext(resp);
            responseObserver.onCompleted();
        }

        @Override
        public void verifyCert(VerifyCertReq req, StreamObserver<VerifyCertResp> responseObserver) {
            logger.info("[verifyCert] Received UserName:" + req.getUsername());
            VerifyCertResp resp;
            try {
                CAClient caClient = newCAClient();
                byte[] cert = Base64.decode(req.getCertcontent());
                ByteArrayInputStream in = new ByteArrayInputStream(cert);
                boolean res = caClient.verifyCert(req.getUsername(), in);
                if (res) {
                    logger.info("[verifyCert]" + req.getUsername() + " Success");
                    resp = VerifyCertResp.newBuilder().setCode(0).build();
                } else {
                    logger.info("[verifyCert]" + req.getUsername() + " Failed");
                    resp = VerifyCertResp.newBuilder().setCode(-1).build();
                }
            } catch (Exception e) {
                e.printStackTrace();
                logger.info("[verifyCert]" + req.getUsername() + " Failed");
                resp = VerifyCertResp.newBuilder().setCode(-1).build();
            }
            responseObserver.onNext(resp);
            responseObserver.onCompleted();
        }

        private void registerUser(String username) throws Exception {
            CAClient caClient = newCAClient();
            ArrayList<Attribute> attList = new ArrayList<Attribute>();
            SampleUser user = caClient.registerUser(username, attList);
            caClient.enrollUser(user, attList);
        }

        private boolean loginUserVerify(String username, byte[] signed, String source) throws Exception {
            CAClient caClient = newCAClient();
            File cardFile = new File("./card/" + username + "/" + username + ".card");
            SampleUser cuser = UserUtils.unSerializeUser(cardFile);
            if (cuser.isRevoked()) {
                logger.info("[Login] User " + username + " has been Revoked");
                return false;
            }
            X509Certificate cert = caClient.getCertificate(username);
            PublicKey ecPublicKey = cert.getPublicKey();
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(ecPublicKey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PublicKey newPublicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            Signature signature = Signature.getInstance("SHA1withECDSA");
            signature.initVerify(newPublicKey);
            signature.update(source.getBytes());
            boolean bool = signature.verify(signed);
            return bool;
        }

        private void revokeUser(String username) throws Exception {
            CAClient caClient = newCAClient();
            File cardFile = new File("./card/" + username + "/" + username + ".card");
            SampleUser ruser = UserUtils.unSerializeUser(cardFile);
            String revoke = caClient.revokeUser(ruser);
            System.out.println("revoke: " + revoke);
        }

        private CAClient newCAClient() throws Exception {
            Path connectionFilePath = Paths.get("./", "connection.json");
            ConnectionProfile connectionProfile = new ConnectionProfile(connectionFilePath.toFile());
            CAClient caClient = new CAClient(connectionProfile.getNetworkConfig().getClientOrganization());
            return caClient;
        }
    }
}
