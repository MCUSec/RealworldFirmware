package iotscope.graph;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.FieldRef;
import soot.jimple.Stmt;
import soot.shimple.DefaultShimpleFactory;
import soot.shimple.Shimple;
import soot.shimple.ShimpleBody;
import soot.shimple.internal.PhiNodeManager;
import soot.util.Chain;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;

import iotscope.utility.AsyncTag;

/**
 * Creates the CallGraph of the application under analysis
 */
public class CallGraph {

    private static final Logger LOGGER = LoggerFactory.getLogger(CallGraph.class);

    // Key the string of the soot method
    // map with the sootMethod name and the CallGraphNode of the sootMethod
    private static final Hashtable<String, CallGraphNode> nodes = new Hashtable<>();

    // Maps Soot Field String to the soot Methods it is referenced
    private static final Hashtable<String, HashSet<SootMethod>> fieldSetters = new Hashtable<>();

    // : Statements where a soot field is referenced. To do symbolic execution on them after
    private static final Hashtable<String, HashSet<SootMethod>> fieldUses = new Hashtable <>();

    public static void init() {
        long startTime = System.currentTimeMillis();

        Chain<SootClass> classes = Scene.v().getClasses();
        try {
            //init the nodes map
            for (SootClass sootClass : classes) {
                List<SootMethod> methods = new ArrayList<>(sootClass.getMethods());
                for (SootMethod sootMethod : methods) {
                    CallGraphNode tmpNode = new CallGraphNode(sootMethod);
                    nodes.put(sootMethod.toString(), tmpNode);
                    if (sootMethod.isConcrete()) {
                        try {
                            sootMethod.retrieveActiveBody();

                            ShimpleBody shimBody = Shimple.v().newBody(sootMethod.getActiveBody());

                            PhiNodeManager pnm = new PhiNodeManager(shimBody, new DefaultShimpleFactory(shimBody));
                            pnm.doEliminatePhiNodes();

                            sootMethod.setActiveBody(shimBody);
                        } catch (Exception e) {
                            LOGGER.error("Could not retrieved the active body of {} because {}", sootMethod, e.getLocalizedMessage());
                        }
                    }
                }
            }

            LOGGER.debug("[CG time]: " + (System.currentTimeMillis() - startTime));
            for (SootClass sootClass : classes) {

                // : Flag to know if we are in a class that we want to analyze
                // : I.e., we dont want to create Asynctask implicit edges for android or androidx
                // : Are there more classes we want to exclude?

                boolean buildAsync = sootClass.toString().startsWith("android") ? false : true;

                for (SootMethod sootMethod : clone(sootClass.getMethods())) {
                    if (!sootMethod.isConcrete())
                        continue;

                    ShimpleBody body = null;
                    try {
                        body = (ShimpleBody) sootMethod.retrieveActiveBody();
                    } catch (Exception e) {
                        LOGGER.error("Could not retrieved the active body of {} because {}", sootMethod, e.getLocalizedMessage());
                    }
                    if (body == null)
                        continue;
                    for (Unit unit : body.getUnits()) {
                        if (unit instanceof Stmt) {
                            if (((Stmt) unit).containsInvokeExpr()) {
                                try {
                                    addCall(sootMethod, ((Stmt) unit).getInvokeExpr().getMethod());
                                } catch (Exception e) {
                                    LOGGER.error(e.getMessage());
                                }

                                // : AsyncTask implicit edge step 1
                                // : Add Tag to method that contains execute call
                                String methodInvoked = ((Stmt) unit).getInvokeExpr().getMethod().toString();
                                if (buildAsync) {
                                    if(methodInvoked.contains("android.os.AsyncTask execute(")) {
                                        AsyncTag t = new AsyncTag("params_execute");
                                            sootMethod.addTag(t);
                                    } 
                                    else if (methodInvoked.contains("void execute(")) {
                                        AsyncTag t = new AsyncTag("runnable_execute");
                                            sootMethod.addTag(t);
                                    }
                                    else if (methodInvoked.contains("android.os.AsyncTask executeOnExecutor(")) {
                                        AsyncTag t = new AsyncTag("executor_execute");
                                            sootMethod.addTag(t);
                                    }
                                }
                               
                            }
                            for (ValueBox valueBox : unit.getDefBoxes()) {
                                Value temporaryValue = valueBox.getValue();
                                if (temporaryValue instanceof FieldRef) {
                                    FieldRef fieldRef = (FieldRef) temporaryValue;
                                    if (fieldRef.getField() == null || fieldRef.getField().getDeclaringClass() == null) {
                                        continue;
                                    }
                                    if (fieldRef.getField().getDeclaringClass().isApplicationClass()) {
                                        String str = fieldRef.getField().toString();
                                        if (!fieldSetters.containsKey(str)) {
                                            LOGGER.info(str);
                                            fieldSetters.put(str, new HashSet<>());
                                        }
                                        fieldSetters.get(str).add(sootMethod);
                                    }
                                }
                            }
                            
                            // : Adding field references in each statement to fieldUses
                            for(ValueBox useBox : unit.getUseBoxes()) {
                                Value temporaryValue = useBox.getValue();
                                if(temporaryValue instanceof FieldRef) {
                                    FieldRef fieldRef = (FieldRef) temporaryValue;
                                    if (fieldRef.getField().getDeclaringClass().isApplicationClass()) {
                                        String str = fieldRef.getField().toString();
                                        if(!fieldUses.containsKey(str)) {
                                            fieldUses.put(str, new HashSet<SootMethod>());
                                        }
                                        fieldUses.get(str).add(sootMethod);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } catch (Throwable e) {
            LOGGER.error("error init call graph");
        }

        LOGGER.info("[CG time]:" + (System.currentTimeMillis() - startTime));
    }

    /**
     * Add to the call graph nodes the information about the callee and caller
     *
     * @param from add to the from node the call information
     * @param to   add to the to node the caller information
     */
    private static void addCall(SootMethod from, SootMethod to) {
        CallGraphNode fromNode, toNode;
        fromNode = getNode(from);
        toNode = getNode(to);
        if (fromNode == null || toNode == null) {
            LOGGER.debug("Can't add call because from or to node is null");
            return;
        }

        fromNode.addCallTo(toNode);
        toNode.addCallBy(fromNode);

    }

    /**
     * get CallGraphNode from Soot Method
     *
     * @param from to get CallGraphNode from
     * @return the corresponding node
     */
    public static CallGraphNode getNode(SootMethod from) {
        return getNode(from.toString());
    }

    /**
     * get CallGraphNode from Soot Method
     *
     * @param from SootMethodString to get the CallGraphNode from
     * @return the corresponding node
     */
    public static CallGraphNode getNode(String from) {
        return nodes.get(from);
    }

    public static HashSet<SootMethod> getSetter(SootField sootField) {
        return fieldSetters.get(sootField.toString());
    }

    /**
     * : get value sof field uses
     */
    public static HashSet<SootMethod> getUses(SootField sootField) {
		return fieldUses.get(sootField.toString());
	}


    public static <T> List<T> clone(List<T> ls) {
        return new ArrayList<T>(ls);
    }
}
