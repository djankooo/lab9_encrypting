package encrypting;

import javafx.application.Application;
import javafx.collections.FXCollections;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.util.Callback;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.awt.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

public class GUI extends Application {

    private FileChooser encryptFileChooser = new FileChooser();
    private FileChooser decryptFileChooser = new FileChooser();

    private ArrayList<Key> keys = new ArrayList();

    private TabPane tabPane = new TabPane();

    private Tab createKeyTab = new Tab("Create key");
    private Tab encryptTab = new Tab("Encrypt");
    private Tab decryptTab = new Tab("Decrypt");

    private GridPane createKeyGridPane;
    private GridPane encryptGridPane;
    private GridPane decryptGridPane;

    private Button createKeyButton = new Button("Create key");
    private Button encryptChooseFileButton = new Button("Choose file");
    private Button decryptChooseFileButton = new Button("Choose file");
    private Button encryptFileButton = new Button("Encrypt key");
    private Button decryptFileButton = new Button("Decrypt key");

    private TextField encryptFilePathTextField = new TextField();
    private TextField decryptFilePathTextField = new TextField();
    private TextField encryptKeyPathTextField = new TextField();
    private TextField decryptKeyPathTextField = new TextField();

    private HBox encryptHBox = new HBox();
    private HBox decryptHBox = new HBox();

    private Label keyIDLabel = new Label("Key ID");

    private Label encryptKeyLabel = new Label("Key ID");
    private Label encryptFileLabel = new Label("File");

    private Label decryptKeyLabel = new Label("Key ID");
    private Label decryptFileLabel = new Label("File");

    private TextField keyIDTextField = new TextField();

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) throws Exception {

        primaryStage.setTitle("Encrypting");

        createKeyGridPane = createGridPane();
        encryptGridPane = createGridPane();
        decryptGridPane = createGridPane();

        setUIControls(primaryStage);

        setTabs();

        primaryStage.setScene(new Scene(tabPane, 1000, 500));
        primaryStage.show();
    }

    private void setTabs() {
        createKeyTab.setContent(createKeyGridPane);
        createKeyTab.setClosable(false);

        encryptTab.setContent(encryptGridPane);
        encryptTab.setClosable(false);

        decryptTab.setContent(decryptGridPane);
        decryptTab.setClosable(false);

        tabPane.getTabs().addAll(createKeyTab, encryptTab, decryptTab);
    }


    private GridPane createGridPane() {
        GridPane gridPane = new GridPane();
        gridPane.setAlignment(Pos.CENTER);
        gridPane.setPadding(new Insets(20, 20, 20, 20));
        return gridPane;
    }

    private void setUIControls(Stage primaryStage) throws Exception {

        createKeyGridPane.add(keyIDLabel, 0, 0);
        createKeyGridPane.add(keyIDTextField, 1, 0);
        createKeyGridPane.add(createKeyButton, 1, 3);

        keyIDTextField.setText("klucz");

        createKeyButton.setMinWidth(primaryStage.getWidth());

        encryptFileChooser.setTitle("Open Resource File");

        encryptHBox.getChildren().addAll(encryptFilePathTextField, encryptChooseFileButton);

        encryptGridPane.add(encryptKeyLabel, 0, 0);
        encryptGridPane.add(encryptKeyPathTextField, 1, 0);
        encryptGridPane.add(encryptFileLabel, 0, 1);
        encryptGridPane.add(encryptHBox, 1, 1);
        encryptGridPane.add(encryptFileButton, 1, 2);

        encryptChooseFileButton.setOnAction(event -> {
            File file = encryptFileChooser.showOpenDialog(primaryStage);
            if (file != null) {
                try {
                    encryptFilePathTextField.setText(file.getCanonicalPath());
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });

        decryptFileChooser.setTitle("Open Resource File");

        decryptHBox.getChildren().addAll(decryptFilePathTextField, decryptChooseFileButton);

        decryptGridPane.add(decryptKeyLabel, 0, 0);
        decryptGridPane.add(decryptKeyPathTextField, 1, 0);
        decryptGridPane.add(decryptFileLabel, 0, 1);
        decryptGridPane.add(decryptHBox, 1, 1);
        decryptGridPane.add(decryptFileButton, 1, 2);

        decryptChooseFileButton.setOnAction(event -> {
            File file = decryptFileChooser.showOpenDialog(primaryStage);
            if (file != null) {
                try {
                    decryptFilePathTextField.setText(file.getCanonicalPath());
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });

        createKeyButton.setOnAction(event -> {
            try {
                doGenkey(keyIDTextField.getText());
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        encryptFileButton.setOnAction( event -> {
            try {
                doEncryptRSAWithAES("C:\\Users\\djankooo\\Desktop\\"+encryptKeyPathTextField.getText()+".key", encryptFilePathTextField.getText());
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        decryptFileButton.setOnAction( event -> {
            try {
                doDecryptRSAWithAES("C:\\Users\\djankooo\\Desktop\\"+decryptKeyPathTextField.getText()+".pub", decryptFilePathTextField.getText());
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    private void doGenkey(String name) throws Exception {

        String fileBase = "C:\\Users\\djankooo\\Desktop\\" + name;
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        try (FileOutputStream out = new FileOutputStream(fileBase + ".key")) {
            out.write(kp.getPrivate().getEncoded());
        }

        try (FileOutputStream out = new FileOutputStream(fileBase + ".pub")) {
            out.write(kp.getPublic().getEncoded());
        }
    }

    private void doEncryptRSAWithAES(String pvtKeyFile, String inputFile) throws Exception {

        byte[] bytes = Files.readAllBytes(Paths.get(pvtKeyFile));
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey pvt = kf.generatePrivate(ks);

        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        SecretKey skey = kgen.generateKey();

        byte[] iv = new byte[128/8];
        Random srandom = new Random();
        srandom.nextBytes(iv);
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        try (FileOutputStream out = new FileOutputStream(inputFile + ".enc")) {
            {
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, pvt);
                byte[] b = cipher.doFinal(skey.getEncoded());
                out.write(b);
                System.err.println("AES Key Length: " + b.length);
            }

            out.write(iv);
            System.err.println("IV Length: " + iv.length);

            Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
            ci.init(Cipher.ENCRYPT_MODE, skey, ivspec);
            try (FileInputStream in = new FileInputStream(inputFile)) {
                processFile(ci, in, out);
            }
        }
    }

    private void doDecryptRSAWithAES(String pubKeyFile, String inputFile) throws Exception {


        byte[] bytes = Files.readAllBytes(Paths.get(pubKeyFile));
        X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pub = kf.generatePublic(ks);

        try (FileInputStream in = new FileInputStream(inputFile)) {
            SecretKeySpec skey = null;
            {
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, pub);
                byte[] b = new byte[256];
                in.read(b);
                byte[] keyb = cipher.doFinal(b);
                skey = new SecretKeySpec(keyb, "AES");
            }

            byte[] iv = new byte[128/8];
            in.read(iv);
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
            ci.init(Cipher.DECRYPT_MODE, skey, ivspec);

            try (FileOutputStream out = new FileOutputStream(inputFile+".ver")){
                processFile(ci, in, out);
            }
        }
    }


    private void processFile(Cipher ci, InputStream in, OutputStream out) throws Exception {
        byte[] ibuf = new byte[1024];
        int len;
        while ((len = in.read(ibuf)) != -1) {
            byte[] obuf = ci.update(ibuf, 0, len);
            if ( obuf != null ) out.write(obuf);
        }
        byte[] obuf = ci.doFinal();
        if ( obuf != null ) out.write(obuf);
    }

}
