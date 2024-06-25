package iotscope.symbolicsimulation;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Stack;

import org.javatuples.Pair;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import iotscope.backwardslicing.CallStackItem;
import iotscope.backwardslicing.StmtPath;
import iotscope.base.ParameterTransferStmt;
import iotscope.base.StmtPoint;
import iotscope.graph.DataDependenciesGraph;
import iotscope.graph.HeapObject;
import iotscope.graph.SValuePoint;
import iotscope.main.Config;
import iotscope.utility.BlockGenerator;
import iotscope.utility.ConstraintUtil;
import soot.Body;
import soot.Local;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.ArrayRef;
import soot.jimple.InvokeExpr;
import soot.jimple.ParameterRef;
import soot.jimple.Stmt;
import soot.jimple.internal.JimpleLocal;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.CompleteBlockGraph;

public class SymbolicContext extends SymbolicStmtSwitch implements StmtPath{

    private static final Logger LOGGER = LoggerFactory.getLogger(SymbolicContext.class);

    private SValuePoint startPoint;

    private Unit currentInstruction;

    private ArrayList<Pair<Block, Integer>> blocks;

    private ArrayList<SootMethod> methods;

    private ArrayList<StmtPoint> execTrace;

    private final Stack<CallStackItem> callStack;

    private List<SymbolicContext> symbolicContextToAdd;

    private boolean finished = false;

    private int symSteps = 0;

    private List<Constraint> constraints;
    
    public SymbolicContext(SymbolicContext oldSymbolicContext) {
        super((HashSet<Value>) oldSymbolicContext.getInterestingVariables().clone(), (HashSet<HeapObject>) oldSymbolicContext.getDependentHeapObjects().clone(), oldSymbolicContext.getDataGraph(), oldSymbolicContext.getConstraints());
        this.startPoint = oldSymbolicContext.getStartPoint();
        this.methods = (ArrayList<SootMethod>) oldSymbolicContext.getMethods().clone();
        this.blocks = (ArrayList<Pair<Block, Integer>>) oldSymbolicContext.getBlocks().clone();
        this.visited = (HashSet<Stmt>) oldSymbolicContext.getVisited().clone();//new ArrayList<>();
        this.currentInstruction = oldSymbolicContext.getCurrentInstruction();
        this.visited.add((Stmt) oldSymbolicContext.getCurrentInstruction());

        this.execTrace = (ArrayList<StmtPoint>) oldSymbolicContext.getExecTrace().clone();
        this.callStack = (Stack<CallStackItem>) oldSymbolicContext.getCallStack().clone();
        this.symSteps = oldSymbolicContext.getSymbolicSteps();

        this.constraints = oldSymbolicContext.getConstraints();
    }

    public List<Constraint> getConstraints() {
        return this.constraints;
    }

    public SymbolicContext(SValuePoint startPoint, DataDependenciesGraph dataGraph) {
        super(dataGraph);

        this.startPoint = startPoint;

        this.constraints = new ArrayList<>();

        this.methods = new ArrayList<>();
        this.methods.add(0, startPoint.getMethodLocation());

        this.callStack = new Stack<>();

        this.blocks = new ArrayList<>();
        setCurrentBlock(startPoint.getBlockLocation());

        this.execTrace = new ArrayList<>();
        this.visited = new HashSet<>();

        this.visited.add((Stmt) startPoint.getInstructionLocation());
        this.currentInstruction = startPoint.getInstructionLocation();

        this.execTrace.add(0, new StmtPoint(startPoint.getMethodLocation(), startPoint.getBlockLocation(),
                startPoint.getInstructionLocation()));

        Local targetLocal = this.startPoint.getTargetLocal();

        if (targetLocal instanceof JimpleLocal) {
            LOGGER.debug("Target Variable is {} {}", targetLocal.getClass(), this.currentInstruction);
            this.addInterestingVariableIfNotConstant(targetLocal);
        }

        LOGGER.info("Target local is %s in statement %s", targetLocal.toString(), this.currentInstruction.toString());
        
    }

    public List<SymbolicContext> oneStepForward() {
        
        symSteps++;

        Unit nextInstructionBlock = this.getCurrentBlock().getSuccOf(this.currentInstruction);

        if (nextInstructionBlock == null && this.getCurrentBlock().getTail() != this.currentInstruction) {
            System.out.println("nextIstructionBlock is null and current instruction is not a tail");
            nextInstructionBlock = this.getCurrentBlock().getBody().getUnits().getSuccOf(this.currentInstruction);
            System.out.println("Try again: " + nextInstructionBlock);
        }

        if (nextInstructionBlock != null) {
            return oneStepForward(nextInstructionBlock);
        } else {

            CompleteBlockGraph completeBlockGraph = BlockGenerator.getInstance().generate(this.getCurrentMethod().retrieveActiveBody(), false);

            List<SymbolicContext> newSymbolicContext = new ArrayList<>();

            List<Block> blocks = BlockGenerator.removeBlocksThatHaveBeenVisitedOnce(this.getBlocks(), completeBlockGraph.getSuccsOf(this.getCurrentBlock()));

            if (blocks.size() == 0) {
                if (this.getCallStack().isEmpty()) {
                    boolean allisParameterRef = true;
                    StringBuilder outputString = new StringBuilder();
                    for (Value var : this.getInterestingVariables()) {
                        outputString.append(var).append(",");
                        if (!(var instanceof ParameterRef)) {
                            allisParameterRef = false;
                        }
                    }
                    //Try to go one step backward to caller, there might be parameter or fields on the path interesting
                    //return oneStepForward2Caller();
                    this.finished = true;
                    return newSymbolicContext;
                } 
                else {// back call
                    getBackFromACall();
                    return newSymbolicContext;
                }
            }
            else {
                this.setCurrentBlock(blocks.get(0));

                for (Block block : blocks) {
                    if (block == this.getCurrentBlock())
                        continue;
                    SymbolicContext tmp;

                    tmp = this.clone();
                    tmp.setCurrentBlock(block);
                    newSymbolicContext.addAll(tmp.oneStepForward(block.getHead()));
                    newSymbolicContext.add(tmp);
                }

                newSymbolicContext.addAll(this.oneStepForward(this.getCurrentBlock().getHead()));
                return newSymbolicContext;
            }
        }        
    }

    public List<SymbolicContext> oneStepForward(Unit nextInstruction) {

        List<SymbolicContext> result = new ArrayList<>();
        this.visited.add((Stmt) nextInstruction);
        currentInstruction = nextInstruction;

        boolean containsInterestingThings = containsInterestingThings(currentInstruction);

        String oldInterestingVariables = this.getInterestingVariableString();

        if (!containsInterestingThings) {
            return result;
        }

        StmtPoint stmt = new StmtPoint(this.getCurrentMethod(), this.getCurrentBlock(), currentInstruction);
        this.getExecTrace().add(0, stmt);

        stmt.getInstructionLocation().apply(this);

        if (getSwitchConstraints() != null) {
            List<Constraint> toAdd = new ArrayList<>();
            for(Constraint c : getSwitchConstraints()) {
                if(c != null){
                    if(!containsConstraint(this.constraints, c)){
                        Constraint newC = c.clone((Stmt)this.currentInstruction);
                        toAdd.add(newC);
                    }
                    if(c.getContextId() == null){
                        c.setContextId((Stmt)this.currentInstruction);
                    }
                }
            }
            this.constraints.addAll(toAdd);
        }

        String newString = this.getInterestingVariableString();
        LOGGER.debug(String.format("Interesting Values:  %s -> %s ", oldInterestingVariables, newString));

        return result;
    }

    private boolean containsConstraint(List<Constraint> constList, Constraint c) {
        for(Constraint item : constList) {
            if(item.equals(c)) {
                return true;
            }
        }
        return false;
    }

    public List<SymbolicContext> oneStepForward2Caller() {
        List<SymbolicContext> result = new ArrayList<>();
        // TODO
        return result;
    }

    @Override
    public boolean diveIntoMethodCall(Value leftOp, boolean leftIsInteresting, InvokeExpr invokeExpr, Value interestingVar) {

        if (!invokeExpr.getMethod().getDeclaringClass().isApplicationClass() || !invokeExpr.getMethod().isConcrete()) {
            return false;
        }

        if (this.getExecTrace().get(0).getInstructionLocation().equals(this.currentInstruction)) {
            this.execTrace.remove(0);
        }

        CallStackItem callStackItem = new CallStackItem(this.getCurrentMethod(), this.getCurrentBlock(), this.getCurrentInstruction(), leftOp);
        this.getCallStack().push(callStackItem);
        HashSet<SootMethod> allMethods = new HashSet<>();
        allMethods.add(invokeExpr.getMethod());

        StmtPoint.findAllSubPointerOfThisMethod(allMethods, invokeExpr.getMethod().getSubSignature(), invokeExpr.getMethod().getDeclaringClass());
        List<Block> heads = new ArrayList<>();
        HashSet<Body> activeBodies = new HashSet<>();
        allMethods.forEach(x -> {
            try {
                activeBodies.add(x.retrieveActiveBody());
            } catch (Exception e) {
                LOGGER.error("Got Exception while retrieving active body {}", e.getLocalizedMessage());
            }
        });

        for (Body body : activeBodies) {
            CompleteBlockGraph completeBlockGraph = BlockGenerator.getInstance().generate(body, false);
            for (Block block : completeBlockGraph.getHeads()) {
                if (leftOp == null) {
                    heads.add(block);
                }
            }
        }

        if (heads.size() == 0) {
            LOGGER.debug(String.format("[%s] [All Head not ReturnStmt]: %s (%s)", this.hashCode(), this.getCurrentInstruction(), this.getCurrentInstruction().getClass()));
        }

        List<SymbolicContext> symbolicContexts = new ArrayList<>();
        int len = heads.size();

        for (int i = 1; i < len; i++) {
            symbolicContexts.add(this.clone());
        }
        symbolicContexts.add(0, this);

        for (int i = 0; i < len; i++) {
            SymbolicContext tempSymbolicContext = symbolicContexts.get(i);
            Block tempBlock = heads.get(i);

            Stmt firstStmt = (Stmt) tempBlock.getHead();

            if ((leftOp != null && leftIsInteresting)) {
                
            }
            else {
                Value interestingParameter = null;
                if(invokeExpr.getArgCount()==0){
                    break;
                }

                int indexArg = -1;
                for (int j = 0; j<invokeExpr.getArgCount(); j++) {
                    Value arg = invokeExpr.getArgs().get(j);
                    if (arg.equivTo(interestingVar)) {
                        indexArg = j;
                    }
                }

                if(indexArg == -1){
                    continue;
                }

                ParameterTransferStmt tmp = new ParameterTransferStmt(interestingVar, tempBlock.getBody().getParameterRefs().get(indexArg));

                Constraint newConst = ConstraintUtil.createConstraint("assign", interestingVar, tempBlock.getBody().getParameterRefs().get(indexArg), (Stmt) tmp);
                constraints.add(newConst);

                StmtPoint tmpStmtPoint = new StmtPoint(this.getCurrentMethod(), this.getCurrentBlock(), tmp);
                tempSymbolicContext.getExecTrace().add(0, tmpStmtPoint);

                tempSymbolicContext.addInterestingVariableIfNotConstant(tempBlock.getBody().getParameterRefs().get(indexArg));
            }

            boolean containsBlock = false;
            for (Pair<Block, Integer> block : blocks) {
                if (tempBlock.equals(block.getValue0())) {
                    containsBlock = true;
                    break;
                }
            }
            if (!containsBlock) {
                tempSymbolicContext.setCurrentMethod(invokeExpr.getMethod());
                tempSymbolicContext.setCurrentBlock(tempBlock); // calls recursive block again
                tempSymbolicContext.setCurrentInstruction(firstStmt);
            }
        }
        symbolicContexts.remove(0);
        symbolicContextToAdd = symbolicContexts;

        return true;

    }

    public void getBackFromACall() {
        CallStackItem citem = this.getCallStack().pop();

        Stmt retStmt = (Stmt) citem.getCurrentInstruction();

        for (Value param : this.getCurrentMethod().getActiveBody().getParameterRefs()) {
            if (this.getInterestingVariables().contains(param)) {

                List<Value> args = retStmt.getInvokeExpr().getArgs();
                int index = ((ParameterRef) param).getIndex();
                if (args.size() <= index) {
                    continue;
                }
                Value opsite = args.get(index);
                this.removeInterestingVariable(param);
                addInterestingVariableIfNotConstant(opsite);
                StmtPoint tmpStmtPoint = new StmtPoint(this.getCurrentMethod(), this.getCurrentBlock(),
                        new ParameterTransferStmt(param, opsite));
                this.getExecTrace().add(0, tmpStmtPoint);
            }
        }

        this.setCurrentMethod(citem.getSootMethod());
        this.setCurrentBlock(citem.getBlock());
        this.setCurrentInstruction(citem.getCurrentInstruction());

    }

    private boolean containsInterestingThings(Unit currentUnit) {
        boolean containsInterestingThings = false;
        for (ValueBox box : currentUnit.getUseAndDefBoxes()) {
            Value currentValue = box.getValue();
            if (getInterestingVariables().contains(currentValue)) {
                containsInterestingThings = true;
                break;
            } else if (currentValue instanceof ArrayRef) {
                Value arrBase = ((ArrayRef) currentValue).getBase();
                if (getInterestingVariables().contains(arrBase)) {
                    containsInterestingThings = true;
                    break;
                }
            }
        }
        return containsInterestingThings;
    }

    public String getInterestingVariableString() {
        StringBuilder result = new StringBuilder();
        for (Value var : this.getInterestingVariables()) {
            result.append(var).append(",");
        }
        return result.toString();
    }

    public boolean symbolicHasFinished() {

        this.finished = this.finished || this.getMethods().size() > Config.MAXMETHODCHAINLEN || this.symSteps > Config.MAXSYMBOLICSTEPS;
        if (this.finished && this.visited != null) {
            this.visited = null;
            this.methods = null;
            this.blocks = null;
        }
        return this.finished;
    }

    public List<SymbolicContext> getSymbolicContextToAdd() {
        return symbolicContextToAdd;
    }

    public void resetSymbolicContextToAdd() {
        symbolicContextToAdd = null;
    }

    public Unit getCurrentInstruction() {
        return currentInstruction;
    }

    public ArrayList<StmtPoint> getExecTrace() {
        return execTrace;
    }

    public ArrayList<SootMethod> getMethods() {
        return methods;
    }

    public SootMethod getCurrentMethod() {
        return getMethods().get(0);
    }

    public Stack<CallStackItem> getCallStack() {
        return callStack;
    }

    public ArrayList<Pair<Block, Integer>> getBlocks() {
        return blocks;
    }

    public Block getCurrentBlock() {
        return getBlocks().get(0).getValue0();
    }

    public void setCurrentInstruction(Unit currentInstruction) {
        this.visited.add((Stmt) currentInstruction);
        this.currentInstruction = currentInstruction;
    }

    public int getSymbolicSteps() {
        return symSteps;
    }

    public SValuePoint getStartPoint() {
        return startPoint;
    }

    public void setCurrentBlock(Block currentBlock) {
        getBlocks().add(0, Pair.with(currentBlock, this.getCallStack().size()));
    }

    public void setCurrentMethod(SootMethod currentMethod) {
        this.getMethods().add(0, currentMethod);
    }

    @Override
    public Unit getStmtPathTail() {
        return this.getExecTrace().get(this.getExecTrace().size() - 1).getInstructionLocation();
    }

    @Override
    public List<StmtPoint> getStmtPath() {
        return this.getExecTrace();
    }

    public void logExecTrace() {
        LOGGER.info("[Start]:" + this.getStartPoint().getInstructionLocation());
        for (StmtPoint var : this.getExecTrace()) {
            LOGGER.info("        " + var.getInstructionLocation());

        }
    }

    public JSONObject toJson() {
        JSONObject result = new JSONObject();

        return result;
    }

    @Override
    public SymbolicContext clone() {
        return new SymbolicContext(this);
    }
}
