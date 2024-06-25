package iotscope.symbolicsimulation;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import iotscope.graph.DataDependenciesGraph;
import iotscope.graph.HeapObject;
import iotscope.utility.ConstraintUtil;
import soot.Local;
import soot.Value;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.ArrayRef;
import soot.jimple.AssignStmt;
import soot.jimple.CastExpr;
import soot.jimple.Constant;
import soot.jimple.FieldRef;
import soot.jimple.IdentityStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.NewArrayExpr;
import soot.jimple.NewExpr;
import soot.jimple.ParameterRef;
import soot.jimple.StaticFieldRef;
import soot.jimple.Stmt;
import soot.jimple.StringConstant;
import soot.jimple.ThisRef;
import soot.jimple.internal.JimpleLocal;

public abstract class SymbolicStmtSwitch extends AbstractStmtSwitch{

    private static final Logger LOGGER = LoggerFactory.getLogger(SymbolicStmtSwitch.class);
    
    private final HashSet<Value> interestingVariables;
    private List<Constraint> constraints;
    private final HashSet<HeapObject> dependentHeapObjects;
    private final DataDependenciesGraph dataGraph;
    HashSet<Stmt> visited;

    public SymbolicStmtSwitch(DataDependenciesGraph dataGraph) {
        this.dataGraph = dataGraph;
        interestingVariables = new HashSet<>();
        dependentHeapObjects = new HashSet<>();

        constraints = new ArrayList<>();
    }

    public SymbolicStmtSwitch(HashSet<Value> interestingVariables, HashSet<HeapObject> dependentHeapObjects, DataDependenciesGraph dataGraph, List<Constraint> constrs) {
        this.interestingVariables = interestingVariables;
        this.dependentHeapObjects = dependentHeapObjects;
        this.dataGraph = dataGraph;

        this.constraints = constrs;
    }

    public HashSet<Stmt> getVisited() {
        if (visited == null) {
            return new HashSet<>();
        }
        return this.visited;
    }

    public HashSet<Value> getInterestingVariables() {
        return interestingVariables;
    }

    public void addInterestingVariableIfNotConstant(Value v) {
        if (v instanceof Local || v instanceof ParameterRef || v instanceof ThisRef) {
            getInterestingVariables().add(v);
        } else if (v instanceof Constant) {
            LOGGER.debug("Variable is constant no need to taint ");
        } else if (v instanceof StaticFieldRef) {
            getInterestingVariables().add(v);
        } else {
            if (v != null) {
                LOGGER.warn(String.format("[%s] [cannot handle addInterestingVariableIfNotConstant] %s(%s)", this.hashCode(), v, v.getClass()));
            }
        }
    }

    public void removeInterestingVariable(Value v) {
        interestingVariables.remove(v);
    }

    public HashSet<HeapObject> getDependentHeapObjects() {
        return dependentHeapObjects;
    }

    public DataDependenciesGraph getDataGraph() {
        return dataGraph;
    }

    public void caseAssignStmt(AssignStmt stmt) {
        Value leftOp = stmt.getLeftOp();
        Value rightOp = stmt.getRightOp();

        //TODO: What if left is array ref?

        boolean isLeftValueInteresting = interestingVariables.contains(leftOp);
        if (isLeftValueInteresting) {
            //keep left op as interesting value if it is an array ref otherwise only the last item is traced, only remove it if there is a new array assigned, or it is initialized
            removeInterestingVariable(leftOp);
        } 
        
        if (rightOp instanceof InvokeExpr) {// 11.6_VirtualInvokeExpr->InvokeExpr
            InvokeExpr rightInvokeExpr = (InvokeExpr) rightOp;
            //String mthSig = tmp.getMethod().toString();
            handleInvokeExpr(leftOp, isLeftValueInteresting, rightInvokeExpr);
            return;
        }
        else if (rightOp instanceof JimpleLocal) {
            boolean isRightValueInteresting = interestingVariables.contains(rightOp);
            if (isRightValueInteresting) {
                addInterestingVariableIfNotConstant(leftOp);
            }
        }
        else if (rightOp instanceof FieldRef) {
            // TODO: handle heap object
        }
        else if (rightOp instanceof CastExpr) {
            this.addInterestingVariableIfNotConstant(((CastExpr) rightOp).getOp());
        }
        else if (rightOp instanceof ArrayRef) {

            Value rightBase = ((ArrayRef) rightOp).getBase();

            boolean isRightBaseInteresting = interestingVariables.contains(rightBase);
            boolean isRightValueInteresting = interestingVariables.contains(rightOp);

            if (isRightBaseInteresting) {
                addInterestingVariableIfNotConstant(leftOp);
                if (!isRightValueInteresting)
                    addInterestingVariableIfNotConstant(rightOp);
            }

            else if (!isRightBaseInteresting)
                this.addInterestingVariableIfNotConstant(rightBase);
            
            Constraint newConst = ConstraintUtil.createConstraint("assign", leftOp, rightOp, null, rightBase);
            constraints.add(newConst);
        }
        else if (rightOp instanceof NewArrayExpr) {
            // TODO
        }
        else if (rightOp instanceof NewExpr) {
            // TODO
        }


    }

    @Override
    public void caseInvokeStmt(InvokeStmt stmt) {
        handleInvokeExpr(null, false, stmt.getInvokeExpr());
    }

    private void handleInvokeExpr(Value leftOp, boolean isLeftValueInteresting, InvokeExpr invokeExpr) {

        String methodSignature = invokeExpr.getMethod().toString();

        boolean isBaseInteresting = false;
        boolean isParamInteresting = false;
        Value base = null;

        Value interestingVar = null;

        if (invokeExpr instanceof InstanceInvokeExpr) {
            base = ((InstanceInvokeExpr) invokeExpr).getBase();
        } else {
            LOGGER.debug("HandleInvokeExpression: Value no InstanceInvokeExpr {}", invokeExpr);
        }

        isBaseInteresting = interestingVariables.contains(base);

        for (Value v : invokeExpr.getArgs()) {
            for(Value w : interestingVariables) {
                if (v.equivTo(w)) {
                    isParamInteresting = true;
                    interestingVar = v;
                    break;
                }
            }
        }

        if (!isBaseInteresting && !isLeftValueInteresting && !isParamInteresting) {
            //otherwise not interesting values are traced and the analysis takes long time
            LOGGER.debug("HandleInvokeExpression: Left Value and base is not interesting therefore it is not further traced");
            return;
        }
        if (methodSignature.toString().contains(" equals(")) {
            if(isBaseInteresting) {
                if(invokeExpr.getArg(0) instanceof StringConstant ) {

                    String right = "STR:" + ((StringConstant) invokeExpr.getArg(0)).value;
                    Constraint newConst = ConstraintUtil.createConstraint("equals", base, right);
                    constraints.add(newConst);
                } else if(invokeExpr.getArg(0) instanceof Local) {
                    Constraint newConst = ConstraintUtil.createConstraint("equals", base, invokeExpr.getArg(0));
                    constraints.add(newConst);
                }
            }
        }
        else if (methodSignature.toString().contains(" contains(")) {
            if(isBaseInteresting) {
                if(invokeExpr.getArg(0) instanceof StringConstant ) {

                    String right = "STR:" + ((StringConstant) invokeExpr.getArg(0)).value;
                    Constraint newConst = ConstraintUtil.createConstraint("contains", base, right);
                    constraints.add(newConst);
                } else if(invokeExpr.getArg(0) instanceof Local) {
                    Constraint newConst = ConstraintUtil.createConstraint("contains", base, invokeExpr.getArg(0));
                    constraints.add(newConst);
                }
            }
        }
        else if (methodSignature.toString().contains(" startsWith(java.lang.String)")) {
            if(invokeExpr.getArg(0) instanceof StringConstant ) {

                String right = "STR:" + ((StringConstant) invokeExpr.getArg(0)).value;

                Constraint equConstr = ConstraintUtil.createConstraint("starts", base, right);
                constraints.add(equConstr);
            } else if(invokeExpr.getArg(0) instanceof Local) {
                Constraint newConst = ConstraintUtil.createConstraint("starts", base, invokeExpr.getArg(0));
                constraints.add(newConst);
            }
        }
        else if (methodSignature.toString().contains(" endsWith(")) {
            if(invokeExpr.getArg(0) instanceof StringConstant ) {

                String right = "STR:" + ((StringConstant) invokeExpr.getArg(0)).value;

                Constraint equConstr = ConstraintUtil.createConstraint("ends", base, right);
                constraints.add(equConstr);
            } else if(invokeExpr.getArg(0) instanceof Local) {
                Constraint newConst = ConstraintUtil.createConstraint("ends", base, invokeExpr.getArg(0));
                constraints.add(newConst);
            }
        }
        else if (methodSignature.toString().contains(" split(")) {
            if(invokeExpr.getArg(0) instanceof StringConstant ) {

                this.addInterestingVariableIfNotConstant(leftOp);

                String right = "STR:";
                String splitArgument = ((StringConstant) invokeExpr.getArg(0)).value;

                if(splitArgument.startsWith("\\")) {
                    //Is a regular expression
                   right += splitArgument.substring(1);
                } else {
                    right += splitArgument;
                }

                Constraint equConstr = ConstraintUtil.createConstraint("equals", leftOp, base);
                Constraint splConstr = ConstraintUtil.createConstraint("split", leftOp, right);
                constraints.add(equConstr);
                constraints.add(splConstr);
            } else if(invokeExpr.getArg(0) instanceof Local) {
                
            }
        }
        else {
            if (!diveIntoMethodCall(leftOp, isLeftValueInteresting, invokeExpr, interestingVar)) {

            }
        }
    }

    @Override
    public void caseIdentityStmt(IdentityStmt stmt) {
        
        // := parameter stmt
        if (this.getInterestingVariables().contains(stmt.getRightOp())) {

            Constraint newConst = ConstraintUtil.createConstraint("assign", stmt.getRightOp(), stmt.getLeftOp());
            constraints.add(newConst);

            this.removeInterestingVariable(stmt.getRightOp());
            if (stmt.getLeftOp() instanceof JimpleLocal) {
                this.addInterestingVariableIfNotConstant(stmt.getLeftOp());
            } else {
                LOGGER.warn(String.format("[%s] [Can't Handle caseIdentityStmt->RightOpUnrecognized]: %s (%s)", this.hashCode(), stmt, stmt.getLeftOp().getClass()));
            }
        } else {
            LOGGER.debug(String.format("[%s] [Can't Handle caseIdentityStmt->LeftOpNotInteresting]: %s (%s)", this.hashCode(), stmt, stmt.getLeftOp().getClass()));
        }
    }


    public List<Constraint> getSwitchConstraints() {
        return this.constraints;
    }

    public abstract boolean diveIntoMethodCall(Value leftOp, boolean leftIsInteresting, InvokeExpr ive, Value interestingVar);

}