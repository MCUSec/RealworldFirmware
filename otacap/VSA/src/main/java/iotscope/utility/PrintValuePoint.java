package iotscope.utility;

import iotscope.backwardslicing.BackwardContext;
import iotscope.base.StmtPoint;
import iotscope.graph.HeapObject;
import iotscope.graph.IDataDependenciesGraphNode;
import iotscope.graph.ValuePoint;
import iotscope.main.Config;
import soot.util.dot.DotGraph;
import soot.util.dot.DotGraphConstants;
import soot.util.dot.DotGraphEdge;
import soot.util.dot.DotGraphNode;

import java.io.File;
import java.util.*;

public class PrintValuePoint {


    /**
     * connect method and its unit
     */
    public final static String CONNECTOR = "--";

    /**
     * prefix for subgraph cluster
     */
    public final static String CLUSTER = "cluster_";

    /**
     * Creates and save the dot graph from the value point
     *
     * @param valuePoint to create dot graph for
     * @param apk        apk name for the output file name
     */
    public static void plotValuePointGraph(ValuePoint valuePoint, String apk) {
        DotGraph dotg = drawValuePoint(valuePoint);
        File apkFile = new File(apk);

        dotg.plot(Config.GRAPH_RESULT_DIR
                + apkFile.getName() + "_"
                + valuePoint.getMethodLocation().getName() + "_BDG.dot");
    }


    private static DotGraph drawValuePoint(ValuePoint valuePoint) {
        DotGraph canvas = initDotGraph(valuePoint, valuePoint.getInstructionLocation().toString());
        List<BackwardContext> backwardContextList = getBackwardContexts(valuePoint, new HashSet<>());
        // Then draw the normal nodes
        drawAllEdgeAndNode(canvas, backwardContextList, false);
        setSubGraphandNodeLabel(canvas, backwardContextList, false);

        return canvas;
    }

    /**
     * Initalize the dot graph canvas
     *
     * @param valuePoint to create dot graph for
     * @param graphname  shown in the graph
     * @return dotgraph canvas
     */
    private static DotGraph initDotGraph(ValuePoint valuePoint, String graphname) {
        DotGraph canvas = new DotGraph(graphname);

        canvas.setGraphLabel(graphname);
        canvas.setNodeShape(DotGraphConstants.NODE_SHAPE_BOX);

        return canvas;
    }

    /**
     * Draw all edges and their nodes.
     * Each node use full name, but label use its own short string.
     * <p>
     * Note that canvas.drawEdge() will also draw the nodes.
     *
     * @param canvas
     */
    private static void drawAllEdgeAndNode(DotGraph canvas, List<BackwardContext> backwardContextList,
                                           final boolean isStaticTrack) {

        Set<String> nodeSet = new HashSet<>();
        Map<String, Set<String>> edgeMap = new HashMap<>();
        for (BackwardContext bc : backwardContextList) {
            StmtPoint prevNode = null;
            for (int i = bc.getStmtPath().size() - 1; i >= 0; i--) {
                StmtPoint stmtPoint = bc.getStmtPath().get(i);
                String sourceStmtPointLabel = stmtPoint.getInstructionLocation().toString() + CONNECTOR + stmtPoint.hashCode();
                if (!nodeSet.contains(sourceStmtPointLabel)) {
                    canvas.drawNode(sourceStmtPointLabel);
                    nodeSet.add(sourceStmtPointLabel);
                    edgeMap.put(sourceStmtPointLabel, new HashSet<>());
                }
                if (prevNode == null) {
                    prevNode = stmtPoint;
                    continue;
                }
                String targetStmtPointLabel = prevNode.getInstructionLocation().toString() + CONNECTOR + prevNode.hashCode();
                if (!edgeMap.get(sourceStmtPointLabel).contains(targetStmtPointLabel)) {
                    DotGraphEdge dotedge = canvas.drawEdge(sourceStmtPointLabel, targetStmtPointLabel);
                    dotedge.setAttribute("color", "black");
                    edgeMap.get(sourceStmtPointLabel).add(targetStmtPointLabel);
                }
                prevNode = stmtPoint;

            }
        }
    }

    /**
     * set each subgraph, and set label for each node
     *
     * @param canvas
     */
    private static void setSubGraphandNodeLabel(DotGraph canvas, List<BackwardContext> backwardContextList,
                                                final boolean isStaticTrack) {


        Set<StmtPoint> tails = getTails(backwardContextList);

        Map<String, Set<StmtPoint>> methodCluster = getMethodMapping(backwardContextList);
        Map<String, Set<String>> classCluster = getClassMapping(backwardContextList);
        for (String className:classCluster.keySet()) {
            String classClusterName = CLUSTER + className;
            DotGraph subgraph = canvas.createSubGraph(classClusterName);
            subgraph.setGraphLabel(className);
            Set<String> methodNodes = classCluster.get(className);

            for (String str_m : methodNodes) {
                String str_cluster = CLUSTER + str_m;

                DotGraph subsubGraph = subgraph.createSubGraph(str_cluster);
                subsubGraph.setGraphLabel(str_m);

                Set<StmtPoint> nodes = methodCluster.get(str_m);
                for (StmtPoint node : nodes) {
                    String str_name = node.getInstructionLocation().toString() + CONNECTOR + node.hashCode();

                    DotGraphNode subnode = subsubGraph.drawNode(str_name);


                    subnode.setLabel(node.getInstructionLocation().toString());
                    /*
                     * Make a color for the init node
                     * Here simply compare string to determine whether it is the init node
                     *
                     * See
                     * http://www.graphviz.org/doc/info/attrs.html
                     * http://www.graphviz.org/doc/info/colors.html
                     */
                    if (tails.contains(node)) {
                        subnode.setAttribute("style", DotGraphConstants.NODE_STYLE_FILLED);
                        subnode.setAttribute("fillcolor", "aquamarine");
                    }
                }
            }
        }

    }

    /**
     * get tails of the value point to color them different
     *
     * @return the tails from the value point
     */
    private static Set<StmtPoint> getTails(List<BackwardContext> backwardContextList) {
        Set<StmtPoint> result = new HashSet<>();
        for (BackwardContext backwardContext : backwardContextList) {
            result.add(backwardContext.getStmtPath().get(0));
        }
        return result;
    }

    /**
     * get a map of method names with all the stmt points occurred in that method to cluster the methods in the graph
     */
    private static Map<String, Set<StmtPoint>> getMethodMapping(List<BackwardContext> backwardContextList) {
        Map<String, Set<StmtPoint>> result = new HashMap<>();
        for (BackwardContext backwardContext : backwardContextList) {
            for (StmtPoint stmtPoint : backwardContext.getStmtPath()) {
                String methodName = stmtPoint.getMethodLocation().toString();
                if (result.containsKey(methodName)) {
                    result.get(methodName).add(stmtPoint);
                } else {
                    result.put(methodName, new HashSet<>());
                    result.get(methodName).add(stmtPoint);
                }
            }
        }
        return result;
    }


    /**
     * Map classes with their method locations for printing a dot graph
     * @param backwardContextList all backward contexts
     */
    private static Map<String, Set<String>> getClassMapping(List<BackwardContext> backwardContextList) {
        Map<String, Set<String>> result = new HashMap<>();
        for (BackwardContext backwardContext : backwardContextList) {
            for (StmtPoint stmtPoint : backwardContext.getStmtPath()) {
                String className = stmtPoint.getMethodLocation().getDeclaringClass().toString();
                if (result.containsKey(className)) {
                    result.get(className).add(stmtPoint.getMethodLocation().toString());
                } else {
                    result.put(className, new HashSet<>());
                    result.get(className).add(stmtPoint.getMethodLocation().toString());
                }
            }
        }
        return result;
    }

    /**
     * Get all backwardcontexts involved in creating the Value point to print a dot graph
     * @param valuePoint to get contexts from
     * @param visited already visited heap objects (ValuePoints)
     * @return list of related backwardContexts
     */
    private static List<BackwardContext> getBackwardContexts(ValuePoint valuePoint, HashSet<HeapObject> visited) {
        List<BackwardContext> result = new ArrayList<>();
        if (valuePoint.getBackwardContexts() != null) {
            result.addAll(valuePoint.getBackwardContexts());
        }
        for (IDataDependenciesGraphNode node:valuePoint.getDependents()) {
            if (node instanceof HeapObject && !visited.contains(node)) {
                visited.add((HeapObject) node);
                for(IDataDependenciesGraphNode heapNode : ((HeapObject) node).getDependents()){
                    if (heapNode instanceof ValuePoint) {
                        List<BackwardContext> bc = getBackwardContexts((ValuePoint) heapNode, visited);
                            result.addAll(bc);
                    }
                }
            }
        }
        return result;
    }


}
