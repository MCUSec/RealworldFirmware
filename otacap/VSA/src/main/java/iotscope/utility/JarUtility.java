package iotscope.utility;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

public class JarUtility {

    private static final Logger LOGGER = LoggerFactory.getLogger(JarUtility.class);


    /**
     * Uses dex2jar to create in the same folder as the apkfile a jar file, which can later be used to load code statically
     *
     * @param dex2jar path to the dex2jar file
     * @param apkPath path to the apk
     */
    public static void apkToJar(String dex2jar, String apkPath) {
        File apkFile = new File(apkPath);
        File directory = new File(apkFile.getParent() + "/jarFiles/");
        if (! directory.exists()){
            directory.mkdir();
        }

        String outputFile = apkFile.getParent() + "/jarFiles/"+ apkFile.getName().replace(".apk", "-dex2jar.jar");
        if (new File(outputFile).exists()) {
            return;
        }
        String apk = apkFile.getAbsolutePath();
        String[] commands = {"sh", "-c", String.format("%s -o %s %s",dex2jar, outputFile, apk)};
        executeCommand(commands);
        if (!(new File(outputFile).exists())) {
            LOGGER.error("Dex2jar throw an error terminating the analysis");
            System.exit(1);
        }
    }


    /**
     * Executes command line commands
     *
     * @param commands to execute
     * @return if it was executed successfully
     */
    private static boolean executeCommand(String[] commands) {
        try {
            Runtime rt = Runtime.getRuntime();
            Process proc = rt.exec(commands);

            BufferedReader stdInput = new BufferedReader(new
                    InputStreamReader(proc.getInputStream()));

            BufferedReader stdError = new BufferedReader(new
                    InputStreamReader(proc.getErrorStream()));

            // Read the output from the command
            String s = null;
            StringBuilder output = new StringBuilder();
            while ((s = stdInput.readLine()) != null) {
                output.append(s);
            }
            System.out.println(output);

            // Read any errors from the attempted command
            String errorOutput = "";
            while ((s = stdError.readLine()) != null) {
                errorOutput += s;
            }
            if (errorOutput.length() > 0) {
                LOGGER.error(errorOutput);
                return false;
            }
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

}
