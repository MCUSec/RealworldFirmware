package iotscope.backwardslicing;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Stack;

import org.javatuples.Pair;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import iotscope.base.ParameterTransferStmt;
import iotscope.base.StmtPoint;
import iotscope.graph.DataDependenciesGraph;
import iotscope.graph.HeapObject;
import iotscope.graph.ValuePoint;
import iotscope.main.Config;
import iotscope.utility.BlockGenerator;
import iotscope.utility.ListUtility;
import soot.Body;
import soot.Local;
import soot.PatchingChain;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.ArrayRef;
import soot.jimple.AssignStmt;
import soot.jimple.ConditionExpr;
import soot.jimple.Constant;
import soot.jimple.IfStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.IntConstant;
import soot.jimple.InvokeExpr;
import soot.jimple.LengthExpr;
import soot.jimple.ParameterRef;
import soot.jimple.ReturnStmt;
import soot.jimple.Stmt;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.internal.JGotoStmt;
import soot.jimple.internal.JIfStmt;
import soot.jimple.internal.JNewArrayExpr;
import soot.jimple.internal.JimpleLocal;
import soot.jimple.toolkits.annotation.logic.Loop;
import soot.jimple.toolkits.annotation.logic.LoopFinder;
import soot.tagkit.Tag;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.CompleteBlockGraph;

public class BackwardContext extends BackwardStmtSwitch implements StmtPath {

    private static final Logger LOGGER = LoggerFactory.getLogger(BackwardContext.class);

    private int backwardSteps = 0;

    private ValuePoint startPoint;

    private ArrayList<SootMethod> methods;
    private ArrayList<Pair<Block, Integer>> blocks;
    private Unit currentInstruction;

    private ArrayList<StmtPoint> execTrace;

    private final Stack<CallStackItem> callStack;
    private List<BackwardContext> backwardContextToAdd;

    private boolean finished = false;

    /**
     * Clone Context
     *
     * @param oldBackwardContext to clone
     */
    public BackwardContext(BackwardContext oldBackwardContext) {
        super((HashSet<Value>) oldBackwardContext.getInterestingVariables().clone(), (HashSet<HeapObject>) oldBackwardContext.getDependentHeapObjects().clone(), oldBackwardContext.getDataGraph());
        this.startPoint = oldBackwardContext.getStartPoint();
        this.methods = (ArrayList<SootMethod>) oldBackwardContext.getMethods().clone();
        this.blocks = (ArrayList<Pair<Block, Integer>>) oldBackwardContext.getBlocks().clone();
        this.visited = (HashSet<Stmt>) oldBackwardContext.getVisited().clone();//new ArrayList<>();
        this.currentInstruction = oldBackwardContext.getCurrentInstruction();
        this.visited.add((Stmt) oldBackwardContext.getCurrentInstruction());

        this.execTrace = (ArrayList<StmtPoint>) oldBackwardContext.getExecTrace().clone();
        this.callStack = (Stack<CallStackItem>) oldBackwardContext.getCallStack().clone();
        this.backwardSteps = oldBackwardContext.getBackwardSteps();
    }


    public List<BackwardContext> getBackwardContextToAdd() {
        return backwardContextToAdd;
    }

    public void resetBackwardContextToAdd() {
        backwardContextToAdd = null;
    }


    /**
     * Create new Backward Context
     *
     * @param startPoint of the backward Context (Instruction from which it gets back traced)
     * @param dataGraph  to back trace
     */
    public BackwardContext(ValuePoint startPoint, DataDependenciesGraph dataGraph) {
        super(dataGraph);
        this.startPoint = startPoint;

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

        // init
        for (int index : this.startPoint.getTargetParamIndexes()) {
            Value tmp;

            if (index == -1) {// set heap object
                tmp = ((JAssignStmt) this.currentInstruction).getRightOp();
            } else if (index == -2) {
                if ((((Stmt) currentInstruction).getInvokeExpr()) instanceof InstanceInvokeExpr) {
                    tmp = ((InstanceInvokeExpr) ((Stmt) currentInstruction).getInvokeExpr()).getBase();
                }else {
                    tmp = null;
                }
            } else {
                tmp = ((Stmt) this.currentInstruction).getInvokeExpr().getArg(index);
            }

            if (tmp instanceof JimpleLocal) {
                LOGGER.debug("Target Variable is {} {}", tmp.getClass(), this.currentInstruction);
                this.addInterestingVariableIfNotConstant(tmp);
            } else if (tmp instanceof Constant) {
                LOGGER.debug("Target Variable is Constant {} {}", tmp.getClass(), this.currentInstruction);
            } else {
                LOGGER.warn("Target Variable is unknown {} {}", tmp , this.currentInstruction);
            }
        }
    }

    /**
     * A context is finished if finished is set, there are no interestingVariables left or the maximal method chain is reached
     *
     * @return true in case the context has finished
     */
    public boolean backWardHasFinished() {
        this.finished = this.finished || super.getInterestingVariables().size() == 0 || this.getMethods().size() > Config.MAXMETHODCHAINLEN || this.backwardSteps > Config.MAXBACKWARDSTEPS;
        if (this.finished && this.visited != null) {
            this.visited = null;
            this.methods = null;
            this.blocks = null;
        }
        return this.finished;
    }


    /**
     * Go one step backwards
     *
     * @return all backward context
     */
    public List<BackwardContext> oneStepBackWard() {
        backwardSteps++;

        Unit nextInstructionBlock = null;
        try {
            nextInstructionBlock = this.getCurrentBlock().getPredOf(this.currentInstruction);
        } catch(Exception e ) {
            return new ArrayList<>();
        }

        if (nextInstructionBlock == null && this.getCurrentBlock().getHead() != this.currentInstruction) {
            nextInstructionBlock = this.getCurrentBlock().getBody().getUnits().getPredOf(this.currentInstruction);
        }

        if (nextInstructionBlock != null) {
            return oneStepBackWard(nextInstructionBlock);
        } else {
            List<BackwardContext> newBackwardContext = new ArrayList<>();


            CompleteBlockGraph completeBlockGraph = BlockGenerator.getInstance().generate(this.getCurrentMethod().retrieveActiveBody(), false);

            // Syncing block
            blockloop:
            for (Block blockSync : completeBlockGraph.getBlocks())
                for (Unit unitSync : blockSync){
                    if(unitSync.equals(this.getCurrentInstruction())) {
                        if(this.getCurrentBlock().equals(blockSync))
                            break blockloop;
                        this.setCurrentBlock(blockSync);
                        break blockloop;
                    }
                }
            
            if (completeBlockGraph.getHeads().contains(this.getCurrentBlock())) {
                if (this.getCallStack().isEmpty()) {
                    boolean allisParameterRef = true;
                    StringBuilder outputString = new StringBuilder();
                    for (Value var : this.getInterestingVariables()) {
                        outputString.append(var).append(",");
                        if (!(var instanceof ParameterRef)) {
                            allisParameterRef = false;
                        }
                    }
                    if (!allisParameterRef) {
                        LOGGER.debug(String.format("[%s] [Not all the interesting values are ParameterRef]: %s", this.hashCode(), outputString.toString()));
                        this.finished = true;
                        return newBackwardContext;
                    }
                    //Try to go one step backward to caller, there might be parameter or fields on the path interesting
                    return oneStepBackWard2Caller();
                } else {// back call
                    getBackFromACall();
                    return newBackwardContext;
                }
            } else {

                // go back to previous block

                // Try to unroll loops
                List<BackwardContext> tmps = handleLoops();
                if (tmps != null)
                    return tmps;
                
                List<Block> blocks = BlockGenerator.removeBlocksThatHaveBeenVisitedOnce(this.getBlocks(),
                        completeBlockGraph.getPredsOf(this.getCurrentBlock()));


                if (blocks.size() == 0) {
                    nextInstructionBlock = this.getCurrentBlock().getBody().getUnits().getPredOf(this.currentInstruction);
                    if (nextInstructionBlock != null && !execTrace.contains(nextInstructionBlock) && !visited.contains(nextInstructionBlock)) {
                        return oneStepBackWard(nextInstructionBlock);
                    }

                    LOGGER.debug(String.format("[%s] [No Predecessor Of]: %s", this.hashCode(), this.getCurrentInstruction()));
                    this.finished = true;
                    return newBackwardContext;
                }

                this.setCurrentBlock(blocks.get(0));

                for (Block block : blocks) {
                    if (block == this.getCurrentBlock())
                        continue;
                    BackwardContext tmp;


                    tmp = this.clone();
                    tmp.setCurrentBlock(block);
                    newBackwardContext.addAll(tmp.oneStepBackWard(block.getTail()));
                    newBackwardContext.add(tmp);
                }

                newBackwardContext.addAll(this.oneStepBackWard(this.getCurrentBlock().getTail()));
                return newBackwardContext;
            }
        }
    }

    private boolean containsInterestingThings(Unit currentUnit) {
        boolean containsInterestingThings = false;
        for (ValueBox box : currentUnit.getUseAndDefBoxes()) {
            Value currentValue = box.getValue();
            if (getInterestingVariables().contains(currentValue)) {
                containsInterestingThings = true;
                break;
            } else if (box.getValue() instanceof ArrayRef && getInterestingVariables().contains(((ArrayRef) box.getValue()).getBase())) {
                containsInterestingThings = true;
                break;
            }
        }
        return containsInterestingThings;
    }

    public List<BackwardContext> oneStepBackWard(Unit nextInstruction) {

        List<BackwardContext> result = new ArrayList<>();
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


        String newString = this.getInterestingVariableString();
        LOGGER.debug(String.format("Interesting Values:  %s -> %s ", oldInterestingVariables, newString));
        return result;
    }

    public List<BackwardContext> oneStepBackWard2Caller() {
        List<BackwardContext> result = new ArrayList<>();
        List<StmtPoint> startPoints = StmtPoint.findCaller(this.getCurrentMethod().toString());
        if (startPoints.size() == 0) {
            SootMethod currentMethod = this.getCurrentMethod();
            if(currentMethod.toString().contains("doInBackground(")) {
                SootClass interestingClass = currentMethod.getDeclaringClass();
                return diveIntoAsyncCall(interestingClass);
            }

            LOGGER.debug(String.format("[%s] [No Caller]: %s ", this.hashCode(), this.getCurrentMethod().toString()));
            this.finished = true;
            return result;

        }

        int len = startPoints.size();
        for (int i = 1; i < len; i++) {
            result.add(0, this.clone());
        }
        result.add(0, this);

        for (int i = 0; i < len; i++) {
            BackwardContext tmpBackwardContext = result.get(i);
            StmtPoint tmpStartPoint = startPoints.get(i);

            tmpBackwardContext.oneStepBackWard2Caller(tmpStartPoint);
        }
        result.remove(0);

        return result;
    }


    public void oneStepBackWard2Caller(StmtPoint tmpSP) {

        this.setCurrentMethod(tmpSP.getMethodLocation());
        this.setCurrentBlock(tmpSP.getBlockLocation());
        this.setCurrentInstruction(tmpSP.getInstructionLocation());

        String oldString = this.getInterestingVariableString();
        LOGGER.debug(String.format("[%s] [Next Ins]: %s (caller:%s)", this.hashCode(), this.getCurrentInstruction(), this.getCurrentMethod()));

        HashMap<Integer, Value> parameterValues = new HashMap<>();

        for (Object var : this.getInterestingVariables()) {
            if (var instanceof ParameterRef) {
                parameterValues.put(((ParameterRef) var).getIndex(), (Value) var);
            }
        }
        this.getInterestingVariables().clear();

        InvokeExpr invokeExpr = ((Stmt) tmpSP.getInstructionLocation()).getInvokeExpr();
        for (int j : parameterValues.keySet()) {
            addInterestingVariableIfNotConstant(invokeExpr.getArg(j));

            ParameterTransferStmt tmp = new ParameterTransferStmt(parameterValues.get(j), invokeExpr.getArg(j));
            StmtPoint tmpStmtPoint = new StmtPoint(this.getCurrentMethod(), this.getCurrentBlock(), tmp);
            this.getExecTrace().add(0, tmpStmtPoint);
        }

        String newString = this.getInterestingVariableString();
        LOGGER.debug(String.format("                 %s -> %s ", oldString, newString));
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

    public ValuePoint getStartPoint() {
        return startPoint;
    }

    public SootMethod getCurrentMethod() {
        return getMethods().get(0);
    }

    public void setCurrentMethod(SootMethod currentMethod) {
        this.getMethods().add(0, currentMethod);
    }

    public Block getCurrentBlock() {
        return getBlocks().get(0).getValue0();
    }

    public void setCurrentBlock(Block currentBlock) {
        getBlocks().add(0, Pair.with(currentBlock, this.getCallStack().size()));
    }

    public ArrayList<SootMethod> getMethods() {
        return methods;
    }

    public ArrayList<Pair<Block, Integer>> getBlocks() {
        return blocks;
    }

    public Unit getCurrentInstruction() {
        return currentInstruction;
    }

    public void setCurrentInstruction(Unit currentInstruction) {
        this.visited.add((Stmt) currentInstruction);
        this.currentInstruction = currentInstruction;
    }

    public String getInterestingVariableString() {
        StringBuilder result = new StringBuilder();
        for (Value var : this.getInterestingVariables()) {
            result.append(var).append(",");
        }
        return result.toString();
    }


    public ArrayList<StmtPoint> getExecTrace() {
        return execTrace;
    }

    public void logExecTrace() {
        LOGGER.info("[Start]:" + this.getStartPoint().getInstructionLocation());
        for (StmtPoint var : this.getExecTrace()) {
            LOGGER.info("        " + var.getInstructionLocation());

        }
    }


    public Stack<CallStackItem> getCallStack() {
        return callStack;
    }

    @Override
    public BackwardContext clone() {
        return new BackwardContext(this);
    }


    @Override
    public boolean diveIntoMethodCall(Value leftOp, boolean leftIsInteresting, InvokeExpr
            invokeExpr) {
        if (!invokeExpr.getMethod().getDeclaringClass().isApplicationClass() || !invokeExpr.getMethod().isConcrete())
            return false;

        if (this.getExecTrace().get(0).getInstructionLocation().equals(this.currentInstruction)) {
            this.execTrace.remove(0);
        } else {
            this.execTrace.remove((Stmt) this.currentInstruction);
        }
        CallStackItem callStackItem = new CallStackItem(this.getCurrentMethod(), this.getCurrentBlock(), this.getCurrentInstruction(), leftOp);
        this.getCallStack().push(callStackItem);
        HashSet<SootMethod> allMethods = new HashSet<>();
        allMethods.add(invokeExpr.getMethod());
        StmtPoint.findAllSubPointerOfThisMethod(allMethods, invokeExpr.getMethod().getSubSignature(), invokeExpr.getMethod().getDeclaringClass());
        List<Block> tails = new ArrayList<>();
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
            for (Block block : completeBlockGraph.getTails()) {
                if (leftOp == null || block.getTail() instanceof ReturnStmt) {
                    tails.add(block);
                }
            }
        }
        if (tails.size() == 0) {
            LOGGER.debug(String.format("[%s] [All Tail not ReturnStmt]: %s (%s)", this.hashCode(), this.getCurrentInstruction(), this.getCurrentInstruction().getClass()));
        }
        List<BackwardContext> backwardContexts = new ArrayList<>();
        int len = tails.size();

        for (int i = 1; i < len; i++) {
            backwardContexts.add(this.clone());
        }
        backwardContexts.add(0, this);

        for (int i = 0; i < len; i++) {
            BackwardContext tempBackwardContext = backwardContexts.get(i);
            Block tempBlock = tails.get(i);

            Stmt returnStmt = (Stmt) tempBlock.getTail();

            if ((leftOp != null && leftIsInteresting)) {
                //map param if interesting
                if (!(tempBlock.getTail() instanceof ReturnStmt)) {
                    LOGGER.error(String.format("[%s] [Tail not ReturnStmt]: %s (%s)", this.hashCode(), tempBlock.getTail(), tempBlock.getTail().getClass()));
                }

                ParameterTransferStmt tmp = new ParameterTransferStmt(leftOp, ((ReturnStmt) returnStmt).getOp());
                StmtPoint tmpStmtPoint = new StmtPoint(this.getCurrentMethod(), this.getCurrentBlock(), tmp);
                tempBackwardContext.getExecTrace().add(0, tmpStmtPoint);

                tempBackwardContext.addInterestingVariableIfNotConstant(((ReturnStmt) returnStmt).getOp());
                // parameter
            }
            boolean containsBlock = false;
            for (Pair<Block, Integer> block : blocks) {
                if (tempBlock.equals(block.getValue0())) {
                    containsBlock = true;
                    break;
                }
            }
            if (!containsBlock) {
                tempBackwardContext.setCurrentMethod(invokeExpr.getMethod());
                tempBackwardContext.setCurrentBlock(tempBlock); // calls recursive block again
                tempBackwardContext.setCurrentInstruction(returnStmt);
            }
        }
        backwardContexts.remove(0);
        backwardContextToAdd = backwardContexts;

        return true;
    }


    public List<BackwardContext> diveIntoAsyncCall(SootClass interestingClass) {
        List<BackwardContext> result = new ArrayList<BackwardContext>();
		ArrayList<StmtPoint> stmtsAsync = new ArrayList<>();
        List<String> asyncTags = List.of("params_execute", "runnable_execute", "executor_execute");
        List<String> candidateLocals = new ArrayList<>();

        for (SootClass sclas : Scene.v().getClasses()) {
			if(sclas.isApplicationClass() && !sclas.toString().startsWith("java") && !sclas.toString().startsWith("android")) {
				for (SootMethod smthd : ListUtility.clone(sclas.getMethods())) {
					if (smthd.isConcrete() && hasAsyncTag(asyncTags, smthd.getTags())) {
                        Body body = smthd.retrieveActiveBody();
                        for(Unit unit : body.getUnits()) {
                            if(unit instanceof JAssignStmt) {
                                Type assignmentClass = ((JAssignStmt) unit).getRightOp().getType();
                                if(assignmentClass.toString().equals(interestingClass.toString())) {
                                    
                                    candidateLocals.add( ((JAssignStmt) unit).getLeftOp().toString() );
                                }
                                    
                            }
                            if(unit.toString().contains(" execute(") || unit.toString().contains(" executeOnExecutor(")) {
                                List<ValueBox> registers = unit.getUseBoxes();
                                if(registers.size()>0) {
                                    String baseRegister = registers.get(0).getValue().toString();
                                    if (candidateLocals.contains(baseRegister)) {
                                        Block block = calcCurrentBlock(smthd, unit);
                                        StmtPoint statementLocation = new StmtPoint(smthd, block, unit);
                                        stmtsAsync.add(statementLocation);
                                    } else {
                                        this.getStartPoint().appendErrors(String.format("[BackwardContext -> diveIntoAsyncCall] Base register is not in candidate locals: %s.", baseRegister));
                                    }
                                }
                            } else {
                                this.getStartPoint().appendErrors(String.format("[BackwardContext -> diveIntoAsyncCall] Something bad happened with statement: %s.", unit));
                            }
                        }
                    }
                }
            }			
        }	

        int length = stmtsAsync.size();
		for (int i = 1; i < length; i++) {
			result.add(0, this.clone());
		}
		result.add(0, this);

        BackwardContext tmpBC;
		StmtPoint tmpSP;
		for (int i = 0; i < length; i++) {
			tmpBC = result.get(i);
			tmpSP = stmtsAsync.get(i);

			tmpBC.oneStepBackWard2Caller(tmpSP);
		}
		result.remove(0);

        return result;
    }

    public boolean hasAsyncTag(List<String> asyncTags, List<Tag> tags) {
        for (Tag tag : tags) {
            if (asyncTags.contains(tag.getName())) {
                return true; // Return true if at least one tag matches
            }
        }
        return false; // Return false if no tag matches
    }

    private Block calcCurrentBlock(SootMethod smthd, Unit u) {
		CompleteBlockGraph cbg = BlockGenerator.getInstance().generate(smthd.getActiveBody(), false);
		for(Block b :cbg.getBlocks()) {
			for(Unit uni : b.getBody().getUnits()) {
				if(u.equals(uni)) {
					return b;
				}
			}
		}
		return null;
	}

    @Override
    public Unit getStmtPathTail() {
        return this.getExecTrace().get(this.getExecTrace().size() - 1).getInstructionLocation();
    }

    @Override
    public List<StmtPoint> getStmtPath() {
        return this.getExecTrace();
    }



    public JSONObject toJson() {
        JSONObject result = new JSONObject();
        if (methods != null) {
            for (SootMethod sm : methods) {
                result.append("methods", sm.toString());
            }
        }
        if (blocks != null) {
            for (Pair<Block, Integer> blk : blocks) {
                result.append("blocks", blk.getValue0().hashCode());
            }
        }

        if (execTrace != null) {
            for (StmtPoint stmt : execTrace) {
                result.append("execTrace", stmt.toJson());
            }
        }

        JSONObject execTraceDetails = new JSONObject();
        HashSet<ValueBox> boxes = new HashSet<>();
        if (execTrace != null) {
            for (StmtPoint stmt : execTrace) {
                boxes.addAll(stmt.getInstructionLocation().getUseAndDefBoxes());
            }
        }
        JSONObject tmp;
        for (ValueBox vb : boxes) {
            tmp = new JSONObject();
            tmp.put("class", vb.getValue().getClass().getSimpleName());
            tmp.put("str", vb.getValue().toString());
            tmp.put("hashCode", vb.getValue().hashCode() + "");

            execTraceDetails.put(vb.getValue().hashCode() + "", tmp);
        }
        result.put("ValueBoxes", execTraceDetails);

        return result;
    }

    public int getBackwardSteps() {
        return backwardSteps;
    }

    public List<BackwardContext> handleLoops() {

        CompleteBlockGraph cbg = null;
		Body methodBody = this.getCurrentMethod().getActiveBody();

		LoopFinder lf = new LoopFinder();
		Set<Loop> loops = lf.getLoops(methodBody);
		if(loops.size()>0) {
            if(unrollLoop(getCurrentMethod(), getCurrentInstruction(), loops)) {
                Body bodygen = this.getCurrentMethod().getActiveBody();
                try {
                    cbg = BlockGenerator.getInstance().generate(bodygen, true);

                }
                catch(Exception e) {
                    this.getStartPoint().appendErrors("[oneStepBackward()]: Error building cfg in oneStepBackwards. Likely is non-tail block with no successors \""+this.getCurrentMethod());
                    //this.finished = true;
                    return new ArrayList<BackwardContext>();
                }
                List<Block> blocks = cbg.getBlocks();
                if(this.execTrace.get(0).getMethodLocation().equals(this.getCurrentMethod())){
                    outerloop:
                    for(int i = blocks.size()-1 ; i>=0; i--) {
                        try {
                            Block b = blocks.get(i);
                            Iterator it = b.iterator();
                            while(it.hasNext()) {
                                Unit un = (Unit) it.next();
                                if(un.equals(execTrace.get(0).getInstructionLocation())) {
                                    if(b.getHead().equals(un) && i>0){
                                        Block b2 = blocks.get(i-1);
                                        this.setCurrentBlock(b2);
                                        this.setCurrentInstruction(b2.getTail());
                                        break outerloop;
                                    } 
                                    else {
                                        this.setCurrentBlock(b);
                                        this.setCurrentInstruction(b.getPredOf(un));
                                        break outerloop;
                                    }
                                }
                            }
                        } catch(Exception e) {
                            this.getStartPoint().appendErrors("[oneStepBackward()]: Error Syncronizing block and unit after loop unroll in \""+this.getCurrentMethod()+"\".");
                        }
                    }
                } else {
                    outerloop:
                    for(int i = blocks.size()-1 ; i>=0; i--) {
                        try {
                            Block b = blocks.get(i);
                            Iterator it = b.iterator();
                            while(it.hasNext()) {
                                Unit un = (Unit) it.next();
                                if(un.equals(this.getCurrentInstruction())){
                                    this.setCurrentBlock(b);
                                    this.setCurrentInstruction(b.getPredOf(un));
                                    break outerloop;
                                }
                            }
                        } catch (Exception e) {
                            System.out.println(e);
                        }
                    }
                    Block defaultBlock = blocks.get(blocks.size()-1);
                    this.setCurrentBlock(defaultBlock);
                    this.setCurrentInstruction(defaultBlock.getTail());
                }
            }
        }

        return null;
    }

    public boolean unrollLoop(SootMethod method, Unit currInst, Set<Loop> loops) {
        int unrollFactor;
        boolean unrolled = false;
        Body body = method.getActiveBody();
        for(Loop loop : loops) {

            unrollFactor = getUnrollFactor(loop.getLoopStatements().get(0), body);

            PatchingChain<Unit> units = body.getUnits();
            List<Stmt> loopStatements = loop.getLoopStatements(); // Get the statements inside the loop

            List<Unit> duplicatedLoopStatements = new ArrayList<>();
            if(unrollFactor>1) {
                for (int i = 0; i < unrollFactor; i++) {
                    for (Unit stmt : loopStatements) {
                        if(stmt instanceof JGotoStmt) {
                            if((((JGotoStmt)stmt).getTarget().equals(loop.getHead()))) {
                                continue;
                            }
                        } else if(stmt instanceof JIfStmt) {
                            if((((JIfStmt)stmt).getTarget().equals(loop.getHead()))) {
                                continue;
                            }
                        }                        
                        duplicatedLoopStatements.add((Unit) stmt.clone());
                    }	
                }
                Unit loopEndStmt = loopStatements.get(loopStatements.size()-1);
                units.insertAfter(duplicatedLoopStatements, loopEndStmt);
                units.removeAll(loopStatements);
                unrolled = true;
            }
        }
        return unrolled;
    }

    public int getUnrollFactor(Stmt first, Body body) {
		int unrollFactor = 0;
		if(first instanceof IfStmt) {
			Value condition = ((IfStmt) first).getCondition();
			Value rightOperand = null;

			if (condition instanceof ConditionExpr) {
			    ConditionExpr conditionExpr = (ConditionExpr) condition;
			    rightOperand = conditionExpr.getOp2();
			    if(conditionExpr.toString().contains(">=") && rightOperand instanceof IntConstant) {
					unrollFactor = Integer.parseInt(rightOperand.toString());
			    } else {
			    	this.getStartPoint().appendErrors("[getUnrollFactor]: Condition \""+conditionExpr+"\" not supported.");
			    }
			}
		} else if(first instanceof AssignStmt) {
			Value rightOperand = ((AssignStmt)first).getRightOp();
			if(!(((AssignStmt)first).getLeftOp() instanceof Local)) {
				this.getStartPoint().appendErrors("[getUnrollFactor]: Loop likely of type while(true) \""+((AssignStmt)first).getLeftOp()+"\".");
			} else { 
				if(rightOperand instanceof LengthExpr) {
					Value arrLocal = ((LengthExpr)rightOperand).getOp();
					if(arrLocal instanceof Local) {
						for(Unit u : body.getUnits()) {
							if(u instanceof AssignStmt) {
								if(((AssignStmt)u).getLeftOp().toString().equals(arrLocal.toString()) && ((AssignStmt)u).getRightOp() instanceof JNewArrayExpr){
									Value v = ((JNewArrayExpr) ((AssignStmt)u).getRightOp()).getSize();
									if(v instanceof IntConstant) {
										unrollFactor = Integer.parseInt(v.toString());
										break;
									} else {
										this.getStartPoint().appendErrors("[getUnrollFactor]: Size of array not a constant int \""+v+"\".");
									}
								}
							}
						}
					}
				} else {
					this.getStartPoint().appendErrors("[getUnrollFactor]: Loop type not supported \""+first+"\".");
				}
			}
		} 
		return unrollFactor;
	}
}
