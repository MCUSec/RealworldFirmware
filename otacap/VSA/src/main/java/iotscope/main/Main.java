package iotscope.main;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.apache.commons.cli.CommandLine;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import iotscope.backwardslicing.BackwardTracing;
import iotscope.base.StmtPoint;
import iotscope.graph.CallGraph;
import iotscope.graph.DataDependenciesGraph;
import iotscope.graph.ValuePoint;
import iotscope.utility.CommunicationDetection;
import iotscope.utility.JarUtility;
import iotscope.utility.PrintValuePoint;
import iotscope.utility.ReflectionHelper;
import iotscope.utility.TimeWatcher;
import iotscope.utility.unknownScheme.CustomURLStreamHandlerFactory;
import soot.PackManager;
import soot.Scene;
import soot.options.Options;

public class Main {

    private static final Logger LOGGER = LoggerFactory.getLogger(Main.class);


    public static boolean outputBackwardContexts;
    public static boolean outputSymbolicContexts;
    public static boolean outputJimpleFiles;

    public static long backTime = 0;

    private static void iniLog(String app) {
        LOGGER.info("Start Analysing {}", app);
        LOGGER.debug("Start Analysing {}", app);
        LOGGER.error("Start Analysing {}", app);
        LOGGER.warn("Start Analysing {}", app);
    }

    private static void endLog() {
        LOGGER.info("---------------------");
        LOGGER.debug("---------------------");
        LOGGER.error("---------------------");
        LOGGER.warn("---------------------");
    }


    private static Thread initIoTScope(String apk, List<String> exclusionList, boolean initSoot, String outputPath, CommandLine cmd) throws IOException {
        LOGGER.info("Setting up soot");
        ApkContext apkContext = ApkContext.getInstance(apk);
        
        File f = new File(apkContext.getPackageName() + ".json");
        if(f.exists()) {
            throw new IllegalArgumentException("Parameter can not be number.");
        }
        
        if (cmd.hasOption(CommandLineOptions.dontOverwriteResult) && getOutputFile(outputPath).exists()) {
            System.exit(0);
        }
        if (initSoot) {
            configureSoot(apkContext, exclusionList);
        }

        LOGGER.info("Loading soot classes");
        try {
            Scene.v().loadNecessaryClasses();
        }catch (Throwable e) {
            LOGGER.error("Soot could not load classes...");
        }
        TimeWatcher timeWatcher = TimeWatcher.getTimeWatcher();
        Thread t = new Thread(timeWatcher);
        t.setDaemon(true);
        t.start();

        LOGGER.info("initialisation of the call graph");
        CallGraph.init();
        return t;
    }

    private static List<ValuePoint> getAllSolvedValuePoints(JSONObject targetMethods, Thread t, String apk) {

        // Data Graph creation
        DataDependenciesGraph dataGraph = new DataDependenciesGraph();

        List<ValuePoint> allValuePoints = new ArrayList<>();
        LOGGER.info("looking for method signatures to trace");
        for (Object jsonObject : targetMethods.getJSONArray("methods")) {

            JSONObject tmp = (JSONObject) jsonObject;

            String tmpSignatureOfMethod = tmp.getString("method");

            //param indexes to trace
            List<Integer> regIndex = new ArrayList<>();
            LOGGER.info(tmp.toString());
            for (Object tob : tmp.getJSONArray("parmIndexs")) {
                regIndex.add((Integer) tob);
            }

            boolean findSubMethods = tmp.has("findSubMethods") && tmp.getBoolean("findSubMethods");
            StmtPoint.createAnnotationMap();
            //match method signature and reg index
            Set<ValuePoint> valuePoints = ValuePoint.find(dataGraph, tmpSignatureOfMethod, regIndex, findSubMethods);
            for (ValuePoint valuePoint : valuePoints) {
                tmp = new JSONObject();
                tmp.put("signatureInApp", tmpSignatureOfMethod);
                valuePoint.setAppendix(tmp);
                LOGGER.info("found ValuePoint {}", valuePoint.getPrintableValuePoint());
            }
            allValuePoints.addAll(valuePoints);
        }
        LOGGER.info("trying to solve the data dependency graph");
        //solving data graph
        dataGraph.solve(allValuePoints);
        if (Config.OUTPUT_GRAPHS) {
            allValuePoints.forEach(x -> PrintValuePoint.plotValuePointGraph(x, apk));
        }

        TimeWatcher.getTimeWatcher().continueMeasurement();
        t.interrupt();
        
        return allValuePoints;

    }
    public static File getOutputFile(String outputPath) {
        File outputFile = new File(outputPath);
        if (outputFile.isDirectory()) {
            outputPath += ApkContext.getInstance().getPackageName() + ".json";
            outputFile= new File(outputPath);
        }
        return outputFile;
    }

    public static void writeOutput(TimeWatcher timeWatcher, long startTime, long initTime, long endTime, String apk, List<ValuePoint> allValuePoints, String outputPath) throws IOException {
        File outputFile = getOutputFile(outputPath);
        //gathering results
        try (Writer writer = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(outputFile), StandardCharsets.UTF_8))) {
            List<ValuePoint> localValuePoints = new LinkedList<>();

            writer.write("{\"ValuePoints\": [");
            int i = 0;
            // long time = 0;
            // long symTime = 0;
            for (ValuePoint valuePoint : allValuePoints) {

                // time += valuePoint.getTime();
                // symTime += valuePoint.getSymTime();
                
                JSONObject tmp = valuePoint.toJson();
                if (CommunicationDetection.isLocalCommunication(valuePoint)) {
                    localValuePoints.add(valuePoint);
                }
                if (tmp.has("ValueSet"))
                    LOGGER.info("Found {} in Method {} with the values {}", tmp.getJSONObject("appendix"), tmp.getString("SootMethod"), tmp.getJSONArray("ValueSet").toString());
                if (i < allValuePoints.size() - 1) {
                    writer.write(tmp.toString() + ",");
                } else {
                    writer.write(tmp.toString());
                }
                i++;
            }
            //Old implementation, saving all results in memory as a json object and write out in the end lead to a outOfMemoryException for some apps
            writer.write("],");
            i = 0;
            writer.write("\"LocalValuePoints\": [");
            
            for (ValuePoint valuePoint : localValuePoints) {
                JSONObject tmp = valuePoint.toJson();
                if (i < localValuePoints.size() - 1) {
                    writer.write(tmp.toString() + ",");
                } else {
                    writer.write(tmp.toString());
                }
                i++;
            }
            //Old implementation, saving all results in memory as a json object and write out in the end lead to a outOfMemoryException for some apps
            writer.write("],");
            if (timeWatcher != null) {
                if (timeWatcher.isTimeoutBackwardUsed()) {
                    writer.write("\"TimeoutBackwardUsed\": \"" + true + "\", ");
                }

                if (timeWatcher.isTimeoutForwardUsed()) {
                    writer.write("\"TimeoutForwardUsed\": \"" + true + "\", ");
                }

                if (timeWatcher.isTimeoutSymbolicUsed()) {
                    writer.write("\"TimeoutSymbolicUsed\": \"" + true + "\", ");
                }
            }
            writer.write("\"backwardsteps\": \"" + (Config.MAXBACKWARDSTEPS) + "\", ");
            writer.write("\"backwardcontext\": \"" + (Config.MAXBACKWARDCONTEXT) + "\", ");
            writer.write("\"timeoutbackward\": \"" + (Config.TIMEOUT_BACKWARDS) + "\", ");
            writer.write("\"timeoutforward\": \"" + (Config.TIMEOUT_FORWARD) + "\", ");

            writer.write("\"packagename\": \"" + apk + "\", ");
            writer.write("\"initTime\": \"" + (initTime - startTime) + "\", ");
            writer.write("\"solveTime\": \"" + (endTime - initTime) + "\",");

            // writer.write("\"BackwardTime\": \"" + backTime + "\", ");
            // writer.write("\"ForwardTime\": \"" + time + "\", ");
            // writer.write("\"SymbolicTime\": \"" + symTime + "\"}");

        }
    }

    public static void analyzeApk(String apk, List<String> exclusionList, JSONObject targetMethods, String outputPath, CommandLine cmd) throws IOException {
        URL.setURLStreamHandlerFactory(new CustomURLStreamHandlerFactory());
        long startTime = System.currentTimeMillis();

        Thread t;
        iniLog(apk);
        try {
        	t = initIoTScope(apk, exclusionList, true, outputPath, cmd);
        } catch (Exception e) {
        	return;
        }
        //Soot configuration and call graph initialisation
        long initTime = System.currentTimeMillis();
        List<ValuePoint> allValuePoints = getAllSolvedValuePoints(targetMethods, t, apk);
        long endTime = System.currentTimeMillis();
        TimeWatcher timeWatcher = TimeWatcher.getTimeWatcher();
        writeOutput(timeWatcher, startTime, initTime, endTime, apk, allValuePoints, outputPath);

        if (Options.v().output_format() == 1) {
            PackManager.v().writeOutput();
        }

        endLog();
        //Trigger GC because old measurement data is not needed anymore
        System.gc();
        soot.G.reset();
    }

    private static List<String> getApksFromFile(String path) {
        List<String> result = new LinkedList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            String line = "";
            while (line != null) {
                line = reader.readLine();
                result.add(line);
            }
        } catch (IOException e) {
            LOGGER.error(e.getMessage());
        }
        return result;
    }

    public static void main(String[] args) throws IOException {
        //Command parsing and setup
        CommandLine cmd = CommandLineOptions.parseOptions(CommandLineOptions.getNewOptions(), args);
        if (cmd == null || cmd.getOptionValue(CommandLineOptions.platform) == null ||
                cmd.getOptionValue(CommandLineOptions.desc) == null || (cmd.getOptionValue(CommandLineOptions.apk) == null && cmd.getOptionValue(CommandLineOptions.listOfApk) == null)) {
            System.exit(1);
        }
        String outputPath = Config.RESULTDIR;

        if (cmd.hasOption(CommandLineOptions.outputPath)) {
            outputPath = cmd.getOptionValue(CommandLineOptions.outputPath);
        }

        if (cmd.hasOption(CommandLineOptions.taintRules)) {
            BackwardTracing.createInstance(cmd.getOptionValue(CommandLineOptions.taintRules));
        }

        if (cmd.hasOption(CommandLineOptions.outputGraph)) {
            Config.OUTPUT_GRAPHS = true;
        }
        if (cmd.hasOption(CommandLineOptions.outputGraphPath)) {
            Config.GRAPH_RESULT_DIR = cmd.getOptionValue(CommandLineOptions.outputGraphPath);
        }
        if (cmd.hasOption(CommandLineOptions.maxBackwardSteps)) {
            Config.MAXBACKWARDSTEPS = Integer.parseInt(cmd.getOptionValue(CommandLineOptions.maxBackwardSteps));
        }
        if (cmd.hasOption(CommandLineOptions.maxBackwardContext)) {
            Config.MAXBACKWARDSTEPS = Integer.parseInt(cmd.getOptionValue(CommandLineOptions.maxBackwardContext));
        }

        if (cmd.hasOption(CommandLineOptions.timeoutBackward)) {
            Config.TIMEOUT_BACKWARDS = Integer.parseInt(cmd.getOptionValue(CommandLineOptions.timeoutBackward)) * 60;
        }
        if (cmd.hasOption(CommandLineOptions.timeoutForward)) {
            Config.TIMEOUT_FORWARD = Integer.parseInt(cmd.getOptionValue(CommandLineOptions.timeoutForward)) * 60;
        }
        outputBackwardContexts = cmd.hasOption(CommandLineOptions.outputBackwardContexts);
        outputJimpleFiles = cmd.hasOption(CommandLineOptions.outputJimpleFiles);
        initDirs(outputPath);

        // set Android jar, which is later needed from soot
        Config.ANDROID_JAR_DIR = cmd.getOptionValue(CommandLineOptions.platform);
        String jarToLoad;
        if (Config.ANDROID_JAR_DIR.endsWith(".jar")) {
            jarToLoad = Config.ANDROID_JAR_DIR;
        } else {
            List<Path> paths = new ArrayList<>();
            Files.list(new File(Config.ANDROID_JAR_DIR).toPath()).forEach(paths::add);
            int max = 0;
            String currentPath = "";
            for (Path path : paths) {
                try{
                    int current = Integer.parseInt(path.getFileName().toString().replace("android-", ""));
                    if (current > max) {
                        max =current;
                        currentPath = path.toString() + "/android.jar";
                    }
                }catch (Exception e) {

                }
            }
            jarToLoad = currentPath;

        }


        //parse description, containing methods to trace
        JSONObject targetMethods = new JSONObject(new String(Files.readAllBytes(Paths.get(cmd.getOptionValue(CommandLineOptions.desc)))));
        //set apk to analyse
        List<String> apksToAnalyse = new LinkedList<>();
        if (cmd.getOptionValue(CommandLineOptions.apk) != null) {
            apksToAnalyse.add(cmd.getOptionValue(CommandLineOptions.apk));
        } else {
            apksToAnalyse.addAll(getApksFromFile(cmd.getOptionValue(CommandLineOptions.listOfApk)));
        }

        // load exclusion list
        List<String> exclusionList = new ArrayList<>();
        if (cmd.getOptionValue(CommandLineOptions.exclusion) != null) {
            LOGGER.info("loading exclusion list");
            JSONObject exclusionJSON = new JSONObject(new String(Files.readAllBytes(Paths.get(cmd.getOptionValue(CommandLineOptions.exclusion)))));
            JSONArray jsonArray = exclusionJSON.getJSONArray("exclude");
            for (int i = 0; i < jsonArray.length(); i++) {
                LOGGER.info("excluded: {}", jsonArray.getString(i));
                exclusionList.add(jsonArray.getString(i));
            }
        }

        JarUtility.apkToJar(cmd.getOptionValue(CommandLineOptions.dex2jar), cmd.getOptionValue(CommandLineOptions.apk));
        ReflectionHelper.init(cmd.getOptionValue(CommandLineOptions.apk), jarToLoad);

        for (String apk : apksToAnalyse) {
            analyzeApk(apk, exclusionList, targetMethods, outputPath, cmd);
        }
        System.exit(0);
    }

    /**
     * create result directories for saving results and logs
     */
    private static void initDirs(String outputPath) {
        File tmp = new File(outputPath);
        if (!tmp.exists()) {
            LOGGER.info("creating tmp directory");
            if (!outputPath.endsWith(".json")) {
                tmp.mkdir();
            }
        }
        tmp = new File(Config.LOGDIR);
        if (!tmp.exists())
            tmp.mkdir();
    }

    /**
     * Configure Soot options
     *
     * @param apkContext    containing the path to the apk file
     * @param exclusionList exclude packages from soot
     */
    public static void configureSoot(ApkContext apkContext, List<String> exclusionList) {
        soot.G.reset();

        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_process_dir(Collections.singletonList(apkContext.getAbsolutePath()));

        if (Config.ANDROID_JAR_DIR.endsWith(".jar")) {
            Options.v().set_force_android_jar(Config.ANDROID_JAR_DIR);
        } else {
            Options.v().set_android_jars(Config.ANDROID_JAR_DIR);

        }

        Options.v().set_process_multiple_dex(true);

        Options.v().set_whole_program(true);
        Options.v().set_allow_phantom_refs(true);
        //switch to output jimple
        Options.v().set_output_dir("jimple/");

        if (outputJimpleFiles) {
            Options.v().set_output_format(Options.output_format_jimple);
        } else {
            Options.v().set_output_format(Options.output_format_none);
        }
        Options.v().set_keep_line_number(true);
        //Options.v().set_keep_offset(true);
        Options.v().ignore_resolution_errors();

        //: use original variables names
        //Options.v().setPhaseOption("jb", "use-original-names:true");

        //List from FlowDroid
        exclusionList.add("java.*");
        exclusionList.add("kotlin.*");
        exclusionList.add("sun.*");
        exclusionList.add("android.*");
        exclusionList.add("org.apache.*");
        exclusionList.add("org.eclipse.*");
        exclusionList.add("soot.*");
        exclusionList.add("javax.*");
        exclusionList.add("rx.*");
        exclusionList.add("org.intellij.lang.*");
        exclusionList.add("org.jetbrains.*");
        exclusionList.add("org.junit.*");
        exclusionList.add("junit.*");
        exclusionList.add("androidx.*");
        exclusionList.add("kotlinx.*");
        exclusionList.add("org.bouncycastle.*");
        exclusionList.add("org.spongycastle.*");

        exclusionList.add("com.google.*");
        exclusionList.add("com.alibaba.*");
        exclusionList.add("com.facebook.*");
        exclusionList.add("okhttp3.*");
        exclusionList.add("okio.*");
        exclusionList.add("com.bumptech.glide.*");
        exclusionList.add("com.google.gson.*");
        exclusionList.add("com.google.protobuf.*");
        exclusionList.add("retrofit.*");
        exclusionList.add("retrofit2.*");
        exclusionList.add("com.fasterxml.jackson.*");
        exclusionList.add("com.squareup.*");
        exclusionList.add("org.json.*");


        //changes for exclude packages
        Options.v().set_exclude(exclusionList);
        Options.v().set_no_bodies_for_excluded(true);
        Options.v().set_ignore_resolution_errors(true);

        //soot.Main.v().autoSetOptions();
    }
}
