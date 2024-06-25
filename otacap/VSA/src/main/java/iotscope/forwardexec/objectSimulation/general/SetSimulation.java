package iotscope.forwardexec.objectSimulation.general;

import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

public class SetSimulation implements SimulationObjects {

    private static final Logger LOGGER = LoggerFactory.getLogger(SetSimulation.class);


    public SetSimulation() {
    }


    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (!signature.contains("Set:")) {
            return null;
        }
        HashSet<Set> result = new HashSet<>();
        if (signature.contains("Set: void <init>(java.util.Collection)>")) {
            HashSet<Collection> currentArguments = SimulationUtil.getCollection(expr.getArg(0), currentValues);
            HashSet<Set> finalResult = result;
            currentArguments.forEach(x -> {
                if (x != null) {
                    finalResult.add(new HashSet(x));
                } else {
                    finalResult.add(new HashSet());
                }
            });
            return finalResult;
        } else if (signature.contains("Set: void <init>")) {
            result.add(new HashSet());
            return result;
        }
        return executeFunction(signature, expr, true, currentValues);
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (!signature.contains("Set:")) {
            return null;
        }
        return executeFunction(signature, expr, false, currentValues);
    }


    private HashSet<?> executeFunction(String signature, InvokeExpr expr, boolean returnBase, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<Set> result = new HashSet<>();
        if (signature.contains("Set: boolean add(java.lang.Object)>")) {
            HashSet<Set> currentBase = SimulationUtil.getSet(((InstanceInvokeExpr) expr).getBase(), currentValues);
            HashSet<Object> currentArg0 = SimulationUtil.getObjectOrConstant(expr.getArg(0), currentValues);
            HashSet<Boolean> returnResult = new HashSet<>();
            for (Set set : currentBase) {
                for (Object o : currentArg0) {
                    returnResult.add(set.add(o));
                }
            }
            if (!returnBase) {
                return returnResult;
            }
            result = currentBase;
        }  else if (signature.contains("Set: boolean addAll(java.util.Collection)>")) {
            HashSet<Set> currentBase = SimulationUtil.getSet(((InstanceInvokeExpr) expr).getBase(), currentValues);
            HashSet<Collection> currentArguments = SimulationUtil.getCollection(expr.getArg(0), currentValues);
            HashSet<Boolean> returnResult = new HashSet<>();

            for (Set set : currentBase) {
                for (Collection arg0 : currentArguments) {
                    returnResult.add(set.addAll(arg0));
                }
            }
            if (!returnBase) {
                return returnResult;
            }
            result = currentBase;
        }  else if (signature.contains("Set: boolean remove(java.lang.Object)>")) {
            HashSet<Set> currentBase = SimulationUtil.getSet(((InstanceInvokeExpr) expr).getBase(), currentValues);
            HashSet<Object> currentArguments = SimulationUtil.getObjectOrConstant(expr.getArg(0), currentValues);
            HashSet<Boolean> returnResult = new HashSet<>();

            for (Set set : currentBase) {
                for (Object arg0 : currentArguments) {
                    returnResult.add(set.remove(arg0));
                }
            }
            if (!returnBase) {
                return returnResult;
            }
            result = currentBase;
        } else if (signature.contains("Set: boolean removeAll(java.util.Collection)>")) {
            HashSet<Set> currentBase = SimulationUtil.getSet(((InstanceInvokeExpr) expr).getBase(), currentValues);
            HashSet<Collection> currentArguments = SimulationUtil.getCollection(expr.getArg(0), currentValues);
            HashSet<Boolean> returnResult = new HashSet<>();

            for (Set set : currentBase) {
                for (Collection arg0 : currentArguments) {
                    returnResult.add(set.removeAll(arg0));
                }
            }
            if (!returnBase) {
                return returnResult;
            }
            result = currentBase;
        }
        return result.size() == 0 ? null : result;
    }


    @Override
    public HashSet<?> handleAssignNewExpression(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        if (rightValue.toString().contains("Set:")) {
            System.out.println("got a List to handle");
        }
        return null;
    }

    @Override
    public HashSet<?> handleAssignConstant(AssignStmt stmt, Value rightValue, Value leftOp, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignNewArrayExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }


    @Override
    public HashSet<?> handleAssignArithmeticExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }


}
