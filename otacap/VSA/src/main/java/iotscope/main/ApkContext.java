package iotscope.main;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmlpull.v1.XmlPullParserException;
import soot.jimple.infoflow.android.axml.ApkHandler;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.jimple.infoflow.android.resources.ARSCFileParser;

import java.io.IOException;


public class ApkContext {
    private static final Logger LOGGER = LoggerFactory.getLogger(ApkContext.class);
    private static ApkContext apkcontext = null;

    public static ApkContext getInstance(String path) throws IOException {
        apkcontext = new ApkContext(path);
        return apkcontext;
    }

    public static ApkContext getInstance() {
        return apkcontext;
    }


    private final ApkHandler apkHandler;
    private ProcessManifest processManifest = null;
    private final ARSCFileParser arscFileParser;


    /**
     * @param path to the apk
     * @throws IOException in case of an error
     */
    private ApkContext(String path) throws IOException {
        this.apkHandler = new ApkHandler(path);

        this.arscFileParser = new ARSCFileParser();
        this.arscFileParser.parse(this.apkHandler.getInputStream("resources.arsc"));
        try {
            this.processManifest = new ProcessManifest(apkHandler.getInputStream("AndroidManifest.xml") , this.arscFileParser );
        } catch (IOException | XmlPullParserException e) {
            LOGGER.error("init failed: {} ", e.getMessage());
        }
        apkHandler.close();
    }

    public String getAbsolutePath() {
        return apkHandler.getAbsolutePath();
    }

    public String getPackageName() {
        try {
            if (processManifest != null)
                return processManifest.getPackageName();

        } catch (Exception e) {
            LOGGER.debug(e.getMessage());
        }

        return null;
    }

    public int getIdentifier(String name, String type) {
        try {
            return arscFileParser.findResourceByName(type, name).getResourceID();
        } catch (Exception e) {
            LOGGER.error("getIdentifier failed for {} of {}", name, type);
            return -1;
        }
    }

    /**
     * @param id to the resource
     * @return the resource string
     */
    public String findResource(int id) {

        String str = "";
        try {
            str = arscFileParser.findResource(id).toString();
        } catch (Exception e) {
            str = String.format("Resources:%d", id);
            LOGGER.error(e.getMessage());
        }
        return str;
    }





}
