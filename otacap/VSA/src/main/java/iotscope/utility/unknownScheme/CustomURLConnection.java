package iotscope.utility.unknownScheme;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
/**
 * Custom URL handler to add unknown as URL protocol without running in any exceptions
 */
public class CustomURLConnection extends URLConnection {

    protected CustomURLConnection(URL url) {
        super(url);
    }

    @Override
    public void connect() throws IOException {
        //not needed we don't want to connect
    }

}