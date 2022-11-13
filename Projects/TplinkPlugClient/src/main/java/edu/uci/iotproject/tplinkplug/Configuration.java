package edu.uci.iotproject.tplinkplug;

import java.io.IOException;
import java.util.MissingResourceException;
import java.util.Objects;
import java.util.Properties;

/**
 * TODO add class documentation.
 *
 * @author Janus Varmarken
 */
public class Configuration {

    /**
     * Name of the file in the resources folder that contains the configuration.
     */
    private static final String RESOURCE_FILENAME = "/cfg/config.properties";

    private static final Properties PROPERTIES;

    // ==== Begin keys used in properties file ====
    private static final String APP_SERVER_URL_KEY = "appServerUrl";
    private static final String LOGIN_TOKEN_KEY = "token";
    private static final String DEVICE_ID_KEY = "deviceId";
    // ===== End keys used in properties file =====

    // ==== Begin cached values of PROPERTIES contents ====
    private static final String APP_SERVER_URL;
    private static final String LOGIN_TOKEN;
    private static final String DEVICE_ID;
    // ===== End cached values of PROPERTIES contents =====

    static {
        PROPERTIES = new Properties();
        try {
            PROPERTIES.load(Configuration.class.getResourceAsStream(RESOURCE_FILENAME));
            APP_SERVER_URL = Objects.requireNonNull(PROPERTIES.getProperty(APP_SERVER_URL_KEY, null),
                    String.format("No value for key '%s' in properties file '%s'", APP_SERVER_URL_KEY, RESOURCE_FILENAME));
            LOGIN_TOKEN = Objects.requireNonNull(PROPERTIES.getProperty(LOGIN_TOKEN_KEY, null),
                    String.format("No value for key '%s' in properties file '%s'", LOGIN_TOKEN_KEY, RESOURCE_FILENAME));
            DEVICE_ID = Objects.requireNonNull(PROPERTIES.getProperty(DEVICE_ID_KEY, null),
                    String.format("No value for key '%s' in properties file '%s'", DEVICE_ID_KEY, RESOURCE_FILENAME));
        } catch (IOException e) {
            e.printStackTrace();
            throw new MissingResourceException(
                    String.format("Configuration file not found in resources. Missing file: '%s'", RESOURCE_FILENAME),
                    Configuration.class.getName(),
                    RESOURCE_FILENAME
            );
        }
    }

    private Configuration() {

    }

    public static String getAppServerUrl() {
        return APP_SERVER_URL;
    }

    public static String getLoginToken() {
        return LOGIN_TOKEN;
    }

    public static final String getDeviceId() {
        return DEVICE_ID;
    }
}
