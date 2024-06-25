package iotscope.main;

public class Config {
    public static String ANDROID_JAR_DIR = "./libs/android.jar";

    public static String RESULTDIR = "./valuesetResult/";
    public static String LOGDIR = "./logs/";

    public static boolean PARSEINTERFACECALL = true;

    public static int MAXMETHODCHAINLEN = 50;

    public static int MAXBACKWARDSTEPS = 300;


    public static int MAXBACKWARDCONTEXT = 600;


    // Kills the process afterwards
    public static int TIMEOUT_BACKWARDS = 15 * 60; //Seconds
    public static int TIMEOUT_FORWARD = 20 * 60; //Seconds

    public static String GRAPH_RESULT_DIR = "./graph/";
    public static boolean OUTPUT_GRAPHS = false;

    // Symbolic variables
    // arbitrary
    public static int MAXSYMCONTEXT = 200;
    // arbitrary
    public static int MAXSYMBOLICSTEPS = 400;

}
