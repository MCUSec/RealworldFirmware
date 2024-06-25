package iotscope.backwardslicing;

import iotscope.graph.DataDependenciesGraph;
import iotscope.graph.HeapObject;
import iotscope.utility.ReflectionHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Local;
import soot.Value;
import soot.jimple.*;
import soot.jimple.internal.AbstractFloatBinopExpr;
import soot.jimple.internal.JimpleLocal;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.HashSet;

public abstract class BackwardStmtSwitch extends AbstractStmtSwitch {

    private static final Logger LOGGER = LoggerFactory.getLogger(BackwardStmtSwitch.class);

    private final HashSet<Value> interestingVariables;
    private final HashSet<HeapObject> dependentHeapObjects;
    private final DataDependenciesGraph dataGraph;
    HashSet<Stmt> visited;


    public BackwardStmtSwitch(DataDependenciesGraph dataGraph) {
        this.dataGraph = dataGraph;
        interestingVariables = new HashSet<>();
        dependentHeapObjects = new HashSet<>();
    }

    public BackwardStmtSwitch(HashSet<Value> interestingVariables, HashSet<HeapObject> dependentHeapObjects, DataDependenciesGraph dataGraph) {
        this.interestingVariables = interestingVariables;
        this.dependentHeapObjects = dependentHeapObjects;
        this.dataGraph = dataGraph;
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
                LOGGER.warn(String.format("[%s] [unknown addInterestingVariableIfNotConstant] %s(%s)", this.hashCode(), v, v.getClass()));
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

    @Override
    public void caseAssignStmt(AssignStmt stmt) {
        Value leftOp = stmt.getLeftOp();
        boolean leftOpIsArrayRef = false;
        if (leftOp instanceof ArrayRef) {            
            leftOpIsArrayRef = true;
        }

        boolean isLeftValueInteresting = false;
        if(leftOpIsArrayRef) {
            isLeftValueInteresting = interestingVariables.contains(((ArrayRef) leftOp).getBase());
        } else{
            isLeftValueInteresting = interestingVariables.contains(leftOp);
        }

        if (isLeftValueInteresting && !leftOpIsArrayRef) {
            //keep left op as interesting value if it is an array ref otherwise only the last item is traced, only remove it if there is a new array assigned, or it is initialized
            removeInterestingVariable(leftOp);
        }
        //keep leftop interesting if it is an array value
        Value rightValue = stmt.getRightOp();
        if (rightValue instanceof InvokeExpr) {// 11.6_VirtualInvokeExpr->InvokeExpr
            InvokeExpr rightInvokeExpr = (InvokeExpr) rightValue;
            handleInvokeExpr(leftOp, isLeftValueInteresting, rightInvokeExpr);
            return;
        }
        if (rightValue instanceof InstanceFieldRef && interestingVariables.contains(((InstanceFieldRef) rightValue).getBase())) {
            isLeftValueInteresting = true;
        }

        if (!isLeftValueInteresting) {
            LOGGER.debug("HandleInvokeExpression: Left Value is not interesting therefore it is not further traced");
            return;
        }

        if (rightValue instanceof NewExpr) {
            NewExpr newExpr = (NewExpr) rightValue;
            String className = newExpr.getBaseType().toString();
            removeInterestingVariable(leftOp);
            LOGGER.debug(String.format("[%s] [Got caseAssignStmt->JNewExpr]: %s (%s) %s", this.hashCode(), stmt, rightValue.getClass(), className));
        } else if (rightValue instanceof NewArrayExpr) {
            NewArrayExpr newArray = (NewArrayExpr) rightValue;
            removeInterestingVariable(leftOp);
            LOGGER.debug(String.format("[%s] [Got caseAssignStmt->JNewExpr]: %s (%s) %s", this.hashCode(), stmt, rightValue.getClass(), newArray.getBaseType().toString()));
        }
        if (rightValue instanceof FieldRef) {
            HeapObject heapObject = HeapObject.getInstance(dataGraph, ((FieldRef) rightValue).getField());
            if (heapObject != null && !this.getDependentHeapObjects().contains(heapObject)) {
                this.getDependentHeapObjects().add(heapObject);
                dataGraph.addNode(heapObject);
            }
        } else if (rightValue instanceof JimpleLocal) {
            this.addInterestingVariableIfNotConstant(rightValue);
        } else if (rightValue instanceof CastExpr) {
            this.addInterestingVariableIfNotConstant(((CastExpr) rightValue).getOp());
        } else if (rightValue instanceof AbstractFloatBinopExpr) {
            Value op1 = ((BinopExpr) rightValue).getOp1();
            Value op2 = ((BinopExpr) rightValue).getOp2();
            this.addInterestingVariableIfNotConstant(op1);
            this.addInterestingVariableIfNotConstant(op2);

        } else if (rightValue instanceof ArrayRef) {
            ArrayRef arrRef = (ArrayRef)rightValue;
            this.addInterestingVariableIfNotConstant(arrRef.getBase());
            this.addInterestingVariableIfNotConstant(arrRef.getIndex());

        } else if (rightValue instanceof Constant) {
            //Returning to avoid logging, nothing to do here because right value is constant, and we don't need to trace it further
            // added the if to avoid unnecessary logging
            return;
        } else if (rightValue instanceof BinopExpr) {
            // + - * /
            BinopExpr be = ((BinopExpr) rightValue);
            this.addInterestingVariableIfNotConstant(be.getOp1());
            this.addInterestingVariableIfNotConstant(be.getOp2());

        } else {
            LOGGER.warn(String.format("[%s] [Got to Handle caseAssignStmt->RightOp]: %s (%s)", this.hashCode(), stmt, rightValue.getClass()));
        }


    }

    @Override
    public void caseInvokeStmt(InvokeStmt stmt) {
        handleInvokeExpr(null, false, stmt.getInvokeExpr());
    }

    private void handleInvokeExpr(Value assignTo, boolean isLeftValueInteresting, InvokeExpr invokeExpr) {
        String mthSig = invokeExpr.getMethod().toString();
        boolean isBaseInteresting = false;
        Value base = null;


        if (invokeExpr instanceof InstanceInvokeExpr) {
            base = ((InstanceInvokeExpr) invokeExpr).getBase();
        } else {
            LOGGER.debug("HandleInvokeExpression: Value no InstanceInvokeExpr {}", invokeExpr);
        }

        isBaseInteresting = interestingVariables.contains(base);

        if (!isBaseInteresting && !isLeftValueInteresting) {
            //otherwise not interesting values are traced and the analysis takes long time
            LOGGER.debug("HandleInvokeExpression: Left Value and base is not interesting therefore it is not further traced");
            return;
        }


        if (mthSig.equals("<java.lang.System: void arraycopy(java.lang.Object,int,java.lang.Object,int,int)>")) {
            if (this.getInterestingVariables().contains(invokeExpr.getArg(2))) {

                this.addInterestingVariableIfNotConstant(invokeExpr.getArg(0));
            }
        } else if (mthSig.equals("<java.lang.String: java.lang.String[] split(java.lang.String)>")) {
            this.addInterestingVariableIfNotConstant(base);
            for (int i : BackwardTracing.getInstance().getInterestedArgIndexes(mthSig, invokeExpr.getArgCount())) {
                this.addInterestingVariableIfNotConstant(invokeExpr.getArg(i));
            }
        }
        
        else if (BackwardTracing.getInstance().hasRuleFor(mthSig)) {

            if (invokeExpr instanceof InstanceInvokeExpr && BackwardTracing.getInstance().isBaseInteresting(mthSig)) {
                this.addInterestingVariableIfNotConstant(((InstanceInvokeExpr) invokeExpr).getBase());
            }
            for (int i : BackwardTracing.getInstance().getInterestedArgIndexes(mthSig, invokeExpr.getArgCount())) {
                this.addInterestingVariableIfNotConstant(invokeExpr.getArg(i));
            }

        } else {
            // if we are not handling it concrete try to dive into the method if it contains interesting soot fields
            //              Or handle it through reflection

            if (!diveIntoMethodCall(assignTo, isLeftValueInteresting, invokeExpr)) {
                LOGGER.warn(String.format("[%s] [Can't Handle handleInvokeExpr->VirtualInvokeExpr]: %s (%s)", this.hashCode(), invokeExpr, invokeExpr.getClass()));

                Class<?> clazz = ReflectionHelper.getClass(invokeExpr.getMethodRef().getDeclaringClass().toString());
                if (clazz != null) {
                    boolean matchesMethod = false;
                    if (invokeExpr.getMethod().isConstructor()) {
                        Constructor<?> c = ReflectionHelper.findMatchingConstructor(clazz, invokeExpr);
                        if (c != null) {
                            matchesMethod = true;
                        }
                    } else {
                        Method m = ReflectionHelper.findMatchingMethod(clazz, invokeExpr);
                        if (m != null) {
                            matchesMethod = true;
                        }
                    }
                    if (matchesMethod) {
                        if (base != null) {
                            this.addInterestingVariableIfNotConstant(base);
                        }
                        for (int i = 0; i < invokeExpr.getArgCount(); i++) {
                            this.addInterestingVariableIfNotConstant(invokeExpr.getArg(i));
                        }
                        return;
                    }
                }
            }         
            
        }

    }

    @Override
    public void caseIdentityStmt(IdentityStmt stmt) {
        // := parameter stmt
        if (this.getInterestingVariables().contains(stmt.getLeftOp())) {
            this.removeInterestingVariable(stmt.getLeftOp());
            if (stmt.getRightOp() instanceof ParameterRef) {
                this.addInterestingVariableIfNotConstant(stmt.getRightOp());
            } else {
                LOGGER.warn(String.format("[%s] [Can't Handle caseIdentityStmt->RightOpUnrecognized]: %s (%s)", this.hashCode(), stmt, stmt.getLeftOp().getClass()));
            }
        } else {
            LOGGER.debug(String.format("[%s] [Can't Handle caseIdentityStmt->LeftOpNotInteresting]: %s (%s)", this.hashCode(), stmt, stmt.getLeftOp().getClass()));
        }
    }

    @Override
    public void defaultCase(Object obj) {
        LOGGER.debug(String.format("[%s] [Can't Handle]: %s (%s)", this.hashCode(), obj, obj.getClass()));
    }


    public abstract boolean diveIntoMethodCall(Value leftOp, boolean leftIsInteresting, InvokeExpr ive);
}
