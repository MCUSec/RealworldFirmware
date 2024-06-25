package iotscope.graph;

import iotscope.symbolicsimulation.SymbolicContext;
import iotscope.base.StmtPoint;
import iotscope.forwardexec.SimulateEngine;
import iotscope.main.Main;
import iotscope.symbolicsimulation.SymbolicController;
import iotscope.utility.CommunicationDetection;
import iotscope.utility.DataProcessing;
import iotscope.utility.StringHelper;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import soot.Local;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.toolkits.graph.Block;

import java.util.*;

public class SValuePoint implements IDataDependenciesGraphNode {

    private static final Logger LOGGER = LoggerFactory.getLogger(SValuePoint.class);

    private final DataDependenciesGraph dataGraph;

    private final SootMethod methodLocation;
    private final Block blockLocation;
    private final Unit instructionLocation;
    private final Local targetLocal;
    private List<SymbolicContext> symbolicContext = null;
    private final HashSet<SymbolicContext> solvedBCs = new HashSet<>();
    private HeapObject creatingHeapObject = null;

    private Object appendix = "";

    private final Map<Integer, Set<Object>> result = new HashMap<>();

    private boolean inited = false;
    private boolean solved = false;

    private long time = 0;

    private LinkedHashSet<String> errors;

    /**
     * @param graph               DataDependenciesGraph
     * @param methodLocation      method of this ValuePoint (same as StmtPoint)
     * @param blockLocation       block of this ValuePoint (same as StmtPoint)
     * @param instructionLocation instruction of this ValuePoint (same as StmtPoint)
     * @param regIndex            parameter index of "interesting" value
     */
    public SValuePoint(DataDependenciesGraph graph, SootMethod methodLocation, Block blockLocation, Unit instructionLocation, Local local) {
        this.dataGraph = graph;
        this.methodLocation = methodLocation;
        this.blockLocation = blockLocation;
        this.instructionLocation = instructionLocation;
        this.targetLocal = local;
        graph.addNode(this);

        errors = new LinkedHashSet<String>();
    }

    public long getTime() {
        return time;
    }

    public void setCreatingHeapObject(HeapObject creatingHeapObjects) {
        this.creatingHeapObject = (creatingHeapObjects);
    }

    public List<SymbolicContext> getSymbolicContexts() {
        return this.symbolicContext;
    }

    public SootMethod getMethodLocation() {
        return this.methodLocation;
    }

    public Block getBlockLocation() {
        return this.blockLocation;
    }

    public Unit getInstructionLocation() {
        return this.instructionLocation;
    }

    public Local getTargetLocal() {
        return this.targetLocal;
    }

    public void setAppendix(Object str) {
        this.appendix = str;
    }

    @Override
    public Set<IDataDependenciesGraphNode> getDependents() {
        HashSet<IDataDependenciesGraphNode> dependents = new HashSet<>();
        if (symbolicContext != null) {
            for (SymbolicContext backwardContext : symbolicContext) {
                HashSet<HeapObject> heapObjects = backwardContext.getDependentHeapObjects();
                dependents.addAll(heapObjects);
            }
        }
        return dependents;
    }

    @Override
    public int getUnsovledDependentsCount() {
        int count = 0;
        for (IDataDependenciesGraphNode node : getDependents()) {
            if (!node.hasSolved()) {
                count++;
            }
        }
        LOGGER.debug(this.hashCode() + "[] unsolved dependencies" + count + " " + symbolicContext.size());
        return count;
    }

    @Override
    public boolean hasSolved() {

        return solved;
    }


    @Override
    public boolean canBePartiallySolve() {
        boolean can = false;
        for (SymbolicContext bc : symbolicContext) {
            if (!solvedBCs.contains(bc)) {
                boolean tmpSolved = true;
                for (HeapObject ho : bc.getDependentHeapObjects()) {
                    if (!ho.hasSolved() && (creatingHeapObject == null || !creatingHeapObject.equals(ho))) {
                        tmpSolved = false;
                        break;
                    }
                }
                if (tmpSolved) {
                    solvedBCs.add(bc);
                    can = true;
                    SimulateEngine tmp = new SimulateEngine(dataGraph, bc);
                    tmp.simulate();
                    mergeResult(bc, tmp);
                }
            }
            for (HeapObject ho : bc.getDependentHeapObjects()) {
                LinkedHashSet<String> tmpErrors = ho.getErrors();
                if(tmpErrors.size() > 0) {
                    errors.addAll(tmpErrors);
                }
            }
        }
        if (can) {
            solved = true;
        }

        return can;
    }

    @Override
    public void solve() {
        long initTime = System.currentTimeMillis();
        solved = true;
        LOGGER.debug("[SOLVING ME]" + this.hashCode());
        for (SymbolicContext symbolicContext : symbolicContext) {
            SimulateEngine tmp = new SimulateEngine(dataGraph, symbolicContext);
            tmp.simulate();
            mergeResult(symbolicContext, tmp);

            LinkedHashSet<String> tmpErrors = tmp.getErrors();
            if(tmpErrors.size() > 0) {
                errors.addAll(tmpErrors);
            }

            for (HeapObject ho : symbolicContext.getDependentHeapObjects()) {
                LinkedHashSet<String> hoErrors = ho.getErrors();
                if(hoErrors.size() > 0) {
                    errors.addAll(hoErrors);
                }
            }
        }
        long endTime = System.currentTimeMillis();
        this.time = endTime - initTime;

        if(result.size() == 0) {
            errors.add(String.format("[SValuePoint -> solve] Could not solve: %s (result set is empty)", this.hashCode()));
        }
        for (Object res : result.values()) {
            if(res == null) {
                errors.add(String.format("[SValuePoint -> solve] Could not solve: %s (result in set is null)", this.hashCode()));
            } else {
                if(res.getClass().toString().contains("HashSet")) {
                    continue;
                }
                String resultObject = "";
                try {
                    resultObject = Objects.toString(res, "");
                } catch(Throwable e) {
                    errors.add(String.format("[SimulateEngine -> caseAssignStmt] Could not convert results to string."));
                }
                if (resultObject.equals("")) {
                    errors.add(String.format("[SValuePoint -> solve] Could not solve: %s (result in set is an empty string)", this.hashCode()));
                }
            }
            
        }
        
    }

    public void mergeResult(SymbolicContext var, SimulateEngine tmp) {

    }

    @Override
    public boolean inited() {
        return inited;
    }

    @Override
    public void initIfHaveNot() {
        inited = true;

        symbolicContext = SymbolicController.getInstance().doForward(this, dataGraph);
    }

    @Override
    public Map<Integer, Set<Object>> getResult() {
        return result;
    }

    /**
     * Find all ValuePoint of a method signature
     *
     * @param dataGraph current DataDependenceGraph
     * @param signature of method to find
     * @param regIndex  parameter indexes to taint
     * @return matching value points
     */
    public static Set<ValuePoint> find(DataDependenciesGraph dataGraph, String signature, List<Integer> regIndex, boolean finSubMethods) {
        Set<ValuePoint> valuePoints = new HashSet<>();

        List<StmtPoint> stmtPoints = StmtPoint.findCaller(signature, finSubMethods);
        for (StmtPoint sp : stmtPoints) {
            // Comment in for debugging and analyze only a specific value point
            //if (sp.getMethodLocation().toString().equals("<com.baidu.lbsapi.auth.LBSAuthManager: void a(java.lang.String,java.lang.String)>")) {
            ValuePoint tmp = new ValuePoint(dataGraph, sp.getMethodLocation(), sp.getBlockLocation(), sp.getInstructionLocation(), regIndex);
            valuePoints.add(tmp);
            //}
        }
        return valuePoints;
    }

    public String getPrintableValuePoint() {
        StringBuilder result = new StringBuilder("\n===============================================================\n");

        //TODO

        // result.append("Class: ").append(methodLocation.getDeclaringClass().toString()).append("\n");
        // result.append("Method: ").append(methodLocation.toString()).append("\n");
        // result.append("Block: " + "\n");
        // if (this.blockLocation != null) {
        //     blockLocation.forEach(u -> {
        //         result.append("       ").append(u).append("\n");
        //     });
        // }
        // targetParams.forEach(u -> {
        //     result.append("              ").append(u).append("\n");
        // });

        return result.toString();
    }


    public String toString() {
        if (!inited)
            return super.toString();
        StringBuilder sb = new StringBuilder();
        sb.append("===========================");
        sb.append(this.hashCode());
        sb.append("===========================\n");
        sb.append("Class: ").append(methodLocation.getDeclaringClass().toString()).append("\n");
        sb.append("Method: ").append(methodLocation.toString()).append("\n");
        sb.append("Target: ").append(instructionLocation.toString()).append("\n");
        sb.append("Solved: ").append(hasSolved()).append("\n");
        sb.append("Depend: ");
        for (IDataDependenciesGraphNode var : this.getDependents()) {
            sb.append(var.hashCode());
            sb.append(", ");
        }
        sb.append("\n");
        sb.append("SymbolicContexts: \n");

        sb.append("ValueSet: \n");
        Map<Integer, Set<Object>> resultMap = result;
        sb.append("  ");
        for (int i : resultMap.keySet()) {
            sb.append(" |").append(i).append(":");
            for (Object str : resultMap.get(i)) {
                sb.append(str == null ? "" : str.toString()).append(",");
            }
        }
        sb.append("\n");

        return sb.toString();
    }

    public JSONObject toJson() {
        JSONObject js = new JSONObject();
        JSONObject tmp;
        Set<DataProcessing> valuePointInformation = CommunicationDetection.analyzeValuePoint(this);

        if (this.getResult() != null) {
            Map<Integer, Set<Object>> var = this.getResult();
            tmp = new JSONObject();
            for (int i : var.keySet()) {
                for (Object str : var.get(i)) {
                    tmp.append(i + "", StringHelper.objectToString(str));
                }
            }
            js.append("ValueSet", tmp);
        }
        if (symbolicContext != null) {
            for (SymbolicContext sc : symbolicContext) {
                if (Main.outputSymbolicContexts) {
                    js.append("SymbolicContexts", sc.toJson());
                }
            }
        }
        js.put("hashCode", this.hashCode() + "");
        js.put("SootMethod", this.getMethodLocation().toString());
        try {
            js.put("startLineNumber", this.getInstructionLocation().getJavaSourceStartLineNumber());
        } catch (Throwable e) {
            LOGGER.error(String.format("Could not add offset of %s", this.getInstructionLocation().toString()));
        }
        js.put("Block", this.getBlockLocation().hashCode());
        js.put("Unit", this.getInstructionLocation());
        js.put("UnitHash", this.getInstructionLocation().hashCode());
        js.put("appendix", appendix);

        if (valuePointInformation.contains(DataProcessing.ENCODED)) {
            js.put("IsPotentiallyEncoded", true);
        }
        if (valuePointInformation.contains(DataProcessing.ENCRYPTED)) {
            js.put("IsPotentiallyEncrypted", true);
        }
        if (valuePointInformation.contains(DataProcessing.FROM_UI)) {
            js.put("IsPotentiallyFromUI", true);
        }
        if (valuePointInformation.contains(DataProcessing.OBFUSCATED)) {
            js.put("IsPotentiallyObfuscated", true);
        }
        if (valuePointInformation.contains(DataProcessing.UPNP)) {
            js.put("UsesPotentiallyUPnP", true);
        }
        if (valuePointInformation.contains(DataProcessing.PROTOBUF)) {
            js.put("UsesPotentiallyProtobuf", true);
        }
        if (valuePointInformation.contains(DataProcessing.JSON)) {
            js.put("UsesPotentiallyJson", true);
        }

        // Uncomment to see errors and warnings in the ValueSet results
        //js.put("Errors", errors);

        return js;
    }


    @Override
    public Set<IDataDependenciesGraphNode> getDirectAndIndirectDependents
            (Set<IDataDependenciesGraphNode> nodesToGetDependents) {
        for (IDataDependenciesGraphNode node : this.getDependents()) {
            if (!nodesToGetDependents.contains(node)) {
                nodesToGetDependents.add(node);
                node.getDirectAndIndirectDependents(nodesToGetDependents);
            }
        }
        return nodesToGetDependents;
    }

    public void appendErrors(String message) {
        errors.add(message);
    }
}
