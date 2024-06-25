package iotscope.graph;

import iotscope.backwardslicing.BackwardContext;
import iotscope.backwardslicing.BackwardController;
import iotscope.base.StmtPoint;
import iotscope.forwardexec.SimulateEngine;
import iotscope.main.Main;
import iotscope.utility.CommunicationDetection;
import iotscope.utility.DataProcessing;
import iotscope.utility.StringHelper;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.*;
import soot.toolkits.graph.Block;

import java.util.*;

public class ValuePoint implements IDataDependenciesGraphNode {

    private static final Logger LOGGER = LoggerFactory.getLogger(ValuePoint.class);

    private final DataDependenciesGraph dataGraph;

    private final SootMethod methodLocation;
    private final Block blockLocation;
    private final Unit instructionLocation;
    //indexes of interesting values
    private final HashSet<Integer> targetParams = new HashSet<>();
    private List<BackwardContext> backwardContexts = null;
    private final HashSet<BackwardContext> solvedBCs = new HashSet<>();
    private HeapObject creatingHeapObject = null;

    private Object appendix = "";

    private final Map<Integer, Set<Object>> result = new HashMap<>();

    private boolean inited = false;
    private boolean solved = false;

    private long time = 0;
    private long symTime = 0;

    private LinkedHashSet<String> errors;

    /**
     * @param graph               DataDependenciesGraph
     * @param methodLocation      method of this ValuePoint (same as StmtPoint)
     * @param blockLocation       block of this ValuePoint (same as StmtPoint)
     * @param instructionLocation instruction of this ValuePoint (same as StmtPoint)
     * @param regIndex            parameter index of "interesting" value
     */
    public ValuePoint(DataDependenciesGraph graph, SootMethod methodLocation, Block blockLocation, Unit instructionLocation, List<Integer> regIndex) {
        this.dataGraph = graph;
        this.methodLocation = methodLocation;
        this.blockLocation = blockLocation;
        this.instructionLocation = instructionLocation;
        this.targetParams.addAll(regIndex);
        graph.addNode(this);

        errors = new LinkedHashSet<String>();
    }


    public void setCreatingHeapObject(HeapObject creatingHeapObjects) {
        this.creatingHeapObject = (creatingHeapObjects);
    }

    public List<BackwardContext> getBackwardContexts() {
        return this.backwardContexts;
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

    public Set<Integer> getTargetParamIndexes() {
        return this.targetParams;
    }

    public void setAppendix(Object str) {
        this.appendix = str;
    }

    @Override
    public Set<IDataDependenciesGraphNode> getDependents() {
        HashSet<IDataDependenciesGraphNode> dependents = new HashSet<>();
        if (backwardContexts != null) {
            for (BackwardContext backwardContext : backwardContexts) {
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
        LOGGER.debug(this.hashCode() + "[] unsolved dependencies" + count + " " + backwardContexts.size());
        return count;
    }

    @Override
    public boolean hasSolved() {

        return solved;
    }


    @Override
    public boolean canBePartiallySolve() {
        boolean can = false;
        for (BackwardContext bc : backwardContexts) {
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
        for (BackwardContext backwardContext : backwardContexts) {
            SimulateEngine tmp = new SimulateEngine(dataGraph, backwardContext);
            tmp.simulate();
            mergeResult(backwardContext, tmp);

            LinkedHashSet<String> tmpErrors = tmp.getErrors();
            if(tmpErrors.size() > 0) {
                errors.addAll(tmpErrors);
            }

            long endTime = System.currentTimeMillis();
            time = endTime - initTime;

            for (HeapObject ho : backwardContext.getDependentHeapObjects()) {
                LinkedHashSet<String> hoErrors = ho.getErrors();
                if(hoErrors.size() > 0) {
                    errors.addAll(hoErrors);
                }
                symTime += ho.getTime();
            }
        }
        
        
        if(result.size() == 0) {
            //TODO log to file that bc did not have a result
            errors.add(String.format("[ValuePoint -> solve] Could not solve: %s (result set is empty)", this.hashCode()));
        }
        for (Object res : result.values()) {
            if(res == null) {
                //TODO log to file that bc did not have a result
                errors.add(String.format("[ValuePoint -> solve] Could not solve: %s (result in set is null)", this.hashCode()));
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
                    //TODO log to file that bc did not have a result
                    errors.add(String.format("[ValuePoint -> solve] Could not solve: %s (result in set is an empty string)", this.hashCode()));
                }
            }
            
        }
        
    }

    public void mergeResult(BackwardContext var, SimulateEngine tmp) {
        HashMap<Value, HashSet<? extends Object>> tmpCurrentValues = tmp.getCurrentValues();
        Value reg;
        for (int i : targetParams) {
            if (i == -1) { //Right part
                reg = ((AssignStmt) var.getStmtPathTail()).getRightOp();
            } else if (i == -2) { //Base object
                if (((Stmt) var.getStmtPathTail()).getInvokeExpr() instanceof InstanceInvokeExpr) {
                    reg = ((InstanceInvokeExpr) ((Stmt) var.getStmtPathTail()).getInvokeExpr()).getBase();
                } else {
                    reg = null;
                }
            } else {
                reg = ((Stmt) var.getStmtPathTail()).getInvokeExpr().getArg(i);
            }
            HashSet<?> toAdd = null;
            if (tmpCurrentValues.containsKey(reg)) {
                try {
                    toAdd = (HashSet<?>) tmpCurrentValues.get(reg).clone();
                } catch (Throwable e) {
                    //cannot do much
                    toAdd = tmpCurrentValues.get(reg);
                }

            } else if (reg instanceof StringConstant) {
                HashSet<String> stringToAdd = new HashSet<>();
                stringToAdd.add(((StringConstant) reg).value);
                toAdd = stringToAdd;
            } else if (reg instanceof IntConstant) {
                HashSet<Integer> integerToAdd = new HashSet<>();
                integerToAdd.add(((IntConstant) reg).value);
                toAdd = integerToAdd;
            } else if (reg instanceof LongConstant) {
                HashSet<Long> longToAdd = new HashSet<>();
                longToAdd.add(((LongConstant) reg).value);
                toAdd = longToAdd;
            } else if (reg instanceof FloatConstant) {
                HashSet<Float> floatToAdd = new HashSet<>();
                floatToAdd.add(((FloatConstant) reg).value);
                toAdd = floatToAdd;
            } else if (reg instanceof DoubleConstant) {
                HashSet<Double> doubleToAdd = new HashSet<>();
                doubleToAdd.add(((DoubleConstant) reg).value);
                toAdd = doubleToAdd;
            }

            if (toAdd != null) {
                try {
                    Set<Object> currentSet = result.getOrDefault(i, new HashSet<>());
                    Set<String> currentStringRepresentation = StringHelper.getStringRepresentations(currentSet);
                    for (Object o : toAdd) {
                        if (!currentStringRepresentation.contains(StringHelper.objectToString(o))) {
                            currentSet.add(o);
                            currentStringRepresentation.add(StringHelper.objectToString(o));
                        }
                    }
                    result.put(i, currentSet);
                } catch (Throwable e) {
                    LOGGER.error("Could not add to the result {}", e.getLocalizedMessage());

                }

            }
        }


    }

    @Override
    public boolean inited() {
        return inited;
    }

    @Override
    public void initIfHaveNot() {
        inited = true;

        backwardContexts = BackwardController.getInstance().doBackWard(this, dataGraph);
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
        result.append("Class: ").append(methodLocation.getDeclaringClass().toString()).append("\n");
        result.append("Method: ").append(methodLocation.toString()).append("\n");
        result.append("Block: " + "\n");
        if (this.blockLocation != null) {
            blockLocation.forEach(u -> {
                result.append("       ").append(u).append("\n");
            });
        }
        targetParams.forEach(u -> {
            result.append("              ").append(u).append("\n");
        });

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
        sb.append("BackwardContexts: \n");

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
        if (backwardContexts != null) {
            for (BackwardContext bc : backwardContexts) {
                if (Main.outputBackwardContexts) {
                    js.append("BackwardContexts", bc.toJson());
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
        // js.put("Errors", errors);

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


    public long getTime() {
        return time;
    }

    public long getSymTime() {
        return symTime;
    }
}
