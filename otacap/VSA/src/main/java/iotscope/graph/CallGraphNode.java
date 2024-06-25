package iotscope.graph;

import soot.SootMethod;

import java.util.HashSet;

/**
 * Current soot Method with the information of which Other method it is called by and to which other method its calling
 */
public class CallGraphNode {

    // SootMethod of the current Node
    private final SootMethod sootMethod;
    //Methods which call this node
    private final HashSet<CallGraphNode> callBy = new HashSet<>();
    //Calls from this Node to others (from this method to other methods)
    private final HashSet<CallGraphNode> callTo = new HashSet<>();

    /**
     * @param sootMethod of this CallGraphNode
     */
    public CallGraphNode(SootMethod sootMethod) {
        this.sootMethod = sootMethod;
    }

    /**
     * Adds caller information
     *
     * @param callingStatement Method which call this Method (Node which call this Node)
     */
    public void addCallBy(CallGraphNode callingStatement) {
        callBy.add(callingStatement);
    }

    /**
     * Adds methods which are called by the current
     *
     * @param method method which is callee
     */
    public void addCallTo(CallGraphNode method) {
        callTo.add(method);
    }

    public HashSet<CallGraphNode> getCallBy() {
        return callBy;
    }


    public SootMethod getSootMethod() {
        return sootMethod;
    }

}
