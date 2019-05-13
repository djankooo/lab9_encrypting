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
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.awt.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;


public class GUI extends Application {

    private Desktop desktop = Desktop.getDesktop();
    private FileChooser encryptFileChooser = new FileChooser();
    private FileChooser decryptFileChooser = new FileChooser();

    private ArrayList<Key> keys = new ArrayList();
    private int iterator = 0;

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

    private ComboBox encryptKeyComboBox;
    private ComboBox decryptKeyComboBox;

    private TextField encryptFilePathTextField = new TextField();
    private TextField decryptFilePathTextField = new TextField();

    private KeyPair keyPair;

    private HBox encryptHBox = new HBox();
    private HBox decryptHBox = new HBox();

    private Label keyIDLabel = new Label("Key ID");
    private Label keyTypeLabel = new Label("Type");
    private Label keyBitsLabel = new Label("Bits");

    private Label encryptKeyLabel = new Label("Key ID");
    private Label encryptFileLabel = new Label("File");

    private Label decryptKeyLabel = new Label("Key ID");
    private Label decryptFileLabel = new Label("File");

    private TextField keyIDTextField = new TextField();
    private TextField keyTypeTextField = new TextField();
    private TextField keyBitsTextField = new TextField();


    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) throws Exception {

        keys.add(new Key( String.valueOf(iterator++), "RSA", 2048));

        primaryStage.setTitle("Encrypting");

        createKeyGridPane = createGridPane();
        encryptGridPane = createGridPane();
        decryptGridPane = createGridPane();


        setTables();

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


    private VBox createVBoxPane() {
        VBox vBox = new VBox();
        vBox.setAlignment(Pos.CENTER);
        vBox.setPadding(new Insets(20, 20, 20, 20));
        return vBox;
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
        createKeyGridPane.add(keyTypeLabel, 0, 1);
        createKeyGridPane.add(keyTypeTextField, 1, 1);
        createKeyGridPane.add(keyBitsLabel, 0, 2);
        createKeyGridPane.add(keyBitsTextField, 1, 2);
        createKeyGridPane.add(createKeyButton, 1, 3);

        keyIDTextField.setText("aaa");
        keyTypeTextField.setText("RSA");
        keyBitsTextField.setText("2048");


        createKeyButton.setMinWidth(primaryStage.getWidth());

        // Encryption

        encryptFileChooser.setTitle("Open Resource File");

        encryptHBox.getChildren().addAll(encryptFilePathTextField, encryptChooseFileButton);

        encryptGridPane.add(encryptKeyLabel, 0, 0);
        encryptGridPane.add(encryptKeyComboBox, 1, 0);
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

        // Decription

        decryptFileChooser.setTitle("Open Resource File");

        decryptHBox.getChildren().addAll(decryptFilePathTextField, decryptChooseFileButton);

        decryptGridPane.add(decryptKeyLabel, 0, 0);
        decryptGridPane.add(decryptKeyComboBox, 1, 0);
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
                keyPair = generateKeyPair(keyTypeTextField.getText(), Integer.valueOf(keyBitsTextField.getText()));
                keys.add(new Key(String.valueOf(iterator++), keyTypeTextField.getText(), Integer.valueOf(keyBitsTextField.getText())));

            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        encryptFileButton.setOnAction( event -> {
            encryptFile(new File (encryptFilePathTextField.getText()));
        });
        decryptFileButton.setOnAction( event -> {
            decryptFile(new File (decryptFilePathTextField.getText()));
        });


    }

    public KeyPair generateKeyPair(String type, int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(type);
        generator.initialize(bits, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        return pair;
    }

    private void encryptFile(File f) {
        try {
//            Key k = (Key) encryptKeyComboBox.getValue();
//            System.out.println(encryptKeyComboBox.getValue());
//            PrivateKey pvt = k.getKeyPair().getPrivate();
            PrivateKey pvt = keys.get(0).getKeyPair().getPrivate();
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pvt);
            try (FileOutputStream out = new FileOutputStream(f.getAbsolutePath() + "_encoded")) {
                byte[] encrypted = cipher.doFinal(Files.readAllBytes(f.toPath()));
                out.write(encrypted);
            } catch (BadPaddingException | IllegalBlockSizeException e) {
                e.printStackTrace();
            }
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IOException e) {
            e.printStackTrace();
        }

    }

    private void decryptFile(File f) {
        try {
            //Key k = (Key) encryptKeyComboBox.getValue();
            //PublicKey pub = k.getKeyPair().getPublic();

            PublicKey pub = keys.get(0).getKeyPair().getPublic();
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, pub);
            try (FileOutputStream out = new FileOutputStream(f.getAbsolutePath() +  "_decoded")) {
                byte[] encrypted = cipher.doFinal(Files.readAllBytes(f.toPath()));
                out.write(encrypted);
            } catch (BadPaddingException | IllegalBlockSizeException e) {
                e.printStackTrace();
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IOException e) {
            e.printStackTrace();
        }

    }


    private void setTables() {

        encryptKeyComboBox = new ComboBox(FXCollections.observableList(keys));
        decryptKeyComboBox = new ComboBox(FXCollections.observableList(keys));

        Callback<ListView<Key>, ListCell<Key>> keysComboBoxFactory = lv -> new ListCell<Key>() {
            @Override
            protected void updateItem(Key item, boolean empty) {
                encryptKeyComboBox = new ComboBox(FXCollections.observableList(keys));
                super.updateItem(item, empty);
                setText(empty ? "" : item.getKeyPairID());
            }

        };

        encryptKeyComboBox.setCellFactory(keysComboBoxFactory);
        encryptKeyComboBox.setButtonCell(keysComboBoxFactory.call(null));


        decryptKeyComboBox.setCellFactory(keysComboBoxFactory);
        decryptKeyComboBox.setButtonCell(keysComboBoxFactory.call(null));

    }
}
