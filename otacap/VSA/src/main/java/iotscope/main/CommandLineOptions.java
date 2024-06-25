package iotscope.main;

import org.apache.commons.cli.*;

public class CommandLineOptions {

    public static String platform = "p";
    public static String apk = "a";
    public static String listOfApk = "l";
    public static String desc = "d";
    public static String exclusion = "e";
    public static String outputPath = "o";
    public static String taintRules = "t";
    public static String outputBackwardContexts = "obc";
    public static String outputJimpleFiles = "oj";
    public static String dex2jar = "dj";
    public static String outputGraph = "og";
    public static String outputGraphPath = "ogp";
    public static String maxBackwardSteps = "mb";
    public static String maxBackwardContext = "mbc";
    public static String dontOverwriteResult = "do";


    public static String timeoutBackward = "tb";
    public static String timeoutForward = "tf";


    public static String onlySpecificFlows = "sf";

    /**
     * Options for IoTScope
     *
     * @return Options object for parsing
     */
    public static Options getNewOptions() {
        Options options = new Options();
        options.addOption(Option.builder(platform).argName("platform").desc("Either the Android platform folder or a concrete android apk").hasArg(true).longOpt("platform").build());
        options.addOption(Option.builder(apk).argName("apk to analyse").desc("The apk to analyse").longOpt("apk").hasArg(true).build());
        options.addOption(Option.builder(listOfApk).argName("list of apk to analyse").desc("A list in a text file with apks to analyse").longOpt("list_apk").hasArg(true).build());

        options.addOption(Option.builder(desc).argName("description of methods").desc("JSON method description").longOpt("desc").hasArg(true).build());
        options.addOption(Option.builder(exclusion).argName("exclusion list").desc("Package exclusion list").longOpt("exclusion").hasArg(true).build());


        options.addOption(Option.builder(outputPath).argName("output folder").desc("The folder where the results are placed in").longOpt("output").hasArg(true).build());
        options.addOption(Option.builder(taintRules).argName("taint rule file").desc("Taint rules json file").longOpt("taint_rule").hasArg(true).build());


        options.addOption(Option.builder(outputBackwardContexts).argName("output backward context").desc("If set the backward contexts are added to the results.").longOpt("output_backward_context").build());
        options.addOption(Option.builder(outputJimpleFiles).argName("output jimple files").desc("If set the jimple files are saved").longOpt("output_jimple_files").build());
        options.addOption(Option.builder(dontOverwriteResult).argName("don't overwrite existing results").desc("If set existing results are not overwritten").longOpt("dont_overwrite").hasArg(false).build());


        options.addOption(Option.builder(dex2jar).argName("dex2jar").desc("Dex2jar file").longOpt("dex2jar").hasArg(true).build());

        options.addOption(Option.builder(outputGraph).argName("output graph files").desc("If set dot graphs are created").longOpt("output_dot_graph").hasArg(false).build());
        options.addOption(Option.builder(outputGraphPath).argName("output path for dot files").desc("Directory where the dot graphs should be placed").longOpt("output_dot_graph_path").hasArg(true).build());

        options.addOption(Option.builder(maxBackwardSteps).argName("number of steps it should trace backward").desc("if the maximal number is reached for the context the backward tracing finish").hasArg(true).build());
        options.addOption(Option.builder(maxBackwardContext).argName("number of backward context it should create").desc("Dex2jar file").longOpt("if the maximum number of backward context per value point is reached no new ones are added").hasArg(true).build());


        options.addOption(Option.builder(timeoutBackward).argName("Timeout backward tracing in minutes").desc("Timeout backward tracing in minutes").longOpt("timeout_backward").hasArg(true).build());
        options.addOption(Option.builder(timeoutForward).argName("Timeout forward computation in minutes").desc("Timeout forward computation in minutes").longOpt("timeout_forward").hasArg(true).build());



        options.addOption(Option.builder(onlySpecificFlows).argName("e").desc("Dex2jar file").longOpt("if the maximum number of backward context per value point is reached no new ones are added").hasArg(true).build());
        return options;

    }

    public static CommandLine parseOptions(Options options, String[] args) {
        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        try {
            return parser.parse(options, args, true);
        } catch (ParseException e) {
            formatter.printHelp("utility-name", options);
        }
        return null;
    }
}
