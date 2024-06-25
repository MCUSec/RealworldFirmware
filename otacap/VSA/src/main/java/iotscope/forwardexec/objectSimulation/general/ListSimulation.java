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

import java.util.*;

public class ListSimulation implements SimulationObjects {

    private static final Logger LOGGER = LoggerFactory.getLogger(ListSimulation.class);


    public ListSimulation() {
    }


    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (!signature.contains("List:")) {
            return null;
        }
        HashSet<List> result = new HashSet<>();
        if (signature.contains("List: void <init>(java.util.Collection)>")) {
            HashSet<Collection> currentArguments = SimulationUtil.getCollection(expr.getArg(0), currentValues);
            HashSet<List> finalResult = result;
            currentArguments.forEach(x -> {
                if (x != null) {
                    finalResult.add(new ArrayList(x));
                } else {
                    finalResult.add(new ArrayList());
                }
            });
            return finalResult;
        } else if (signature.contains("List: void <init>")) {
            result.add(new ArrayList());
            return result;
        }
        return executeFunction(signature, expr, true, currentValues);
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (!signature.contains("List:")) {
            return null;
        }
        if (signature.contains("List: java.lang.Object get(int)>")) {
            HashSet<List> currentBase = SimulationUtil.getList(((InstanceInvokeExpr) expr).getBase(), currentValues);
            HashSet<Integer> currentArg0 = SimulationUtil.getIntContent(expr.getArg(0), currentValues);
            HashSet<Object> results = new HashSet<>();
            for (List list : currentBase) {
                for (Integer o : currentArg0) {
                    if (o >= 0 && o < list.size()) {
                        results.add(list.get(o));
                    } else if (o == -1 && list.size() > 0) {
                        results.add(list.get(0));
                    }
                }
            }
            return results;
        }

        return executeFunction(signature, expr, false, currentValues);
    }


    private HashSet<?> executeFunction(String signature, InvokeExpr expr, boolean returnBase, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<List> result = new HashSet<>();
        if (signature.contains("List: boolean add(java.lang.Object)>")) {
            HashSet<List> currentBase = SimulationUtil.getList(((InstanceInvokeExpr) expr).getBase(), currentValues);
            HashSet<Object> currentArg0 = SimulationUtil.getObjectOrConstant(expr.getArg(0), currentValues);
            HashSet<Boolean> returnResult = new HashSet<>();
            for (List list : currentBase) {
                for (Object o : currentArg0) {
                    returnResult.add(list.add(o));
                }
            }
            if (!returnBase) {
                return returnResult;
            }
            result = currentBase;
        } else if (signature.contains("List: void add(int,java.lang.Object)")) {
            HashSet<List> currentBase = SimulationUtil.getList(((InstanceInvokeExpr) expr).getBase(), currentValues);
            HashSet<Integer> currentArg0 = SimulationUtil.getIntContent(expr.getArg(0), currentValues);
            HashSet<Object> currentArg1 = SimulationUtil.getObjectOrConstant(expr.getArg(1), currentValues);
            for (List list : currentBase) {
                for (Integer arg0 : currentArg0) {
                    for (Object arg1 : currentArg1) {
                        try {
                            list.add(arg0, arg1);
                        } catch (IndexOutOfBoundsException e) {
                            list.add(arg1);
                        }
                    }
                }
            }
        } else if (signature.contains("List: boolean addAll(java.util.Collection)>")) {
            HashSet<List> currentBase = SimulationUtil.getList(((InstanceInvokeExpr) expr).getBase(), currentValues);
            HashSet<Collection> currentArguments = SimulationUtil.getCollection(expr.getArg(0), currentValues);
            HashSet<Boolean> returnResult = new HashSet<>();

            for (List list : currentBase) {
                for (Collection arg0 : currentArguments) {
                    returnResult.add(list.addAll(arg0));
                }
            }
            if (!returnBase) {
                return returnResult;
            }
            result = currentBase;
        } else if (signature.contains("List: boolean addAll(int,java.util.Collection)>")) {
            HashSet<List> currentBase = SimulationUtil.getList(((InstanceInvokeExpr) expr).getBase(), currentValues);
            HashSet<Integer> currentArg0 = SimulationUtil.getIntContent(expr.getArg(0), currentValues);
            HashSet<Collection> currentArg1 = SimulationUtil.getCollection(expr.getArg(1), currentValues);
            HashSet<Boolean> returnResult = new HashSet<>();

            for (List list : currentBase) {
                for (Integer arg0 : currentArg0) {
                    for (Collection arg1 : currentArg1) {
                        if (list.size() >= arg0 && arg0>= 0) {
                            returnResult.add(list.addAll(arg0, arg1));
                        } else {
                            returnResult.add(list.addAll(arg1));
                        }
                    }
                }
            }
            if (!returnBase) {
                return returnResult;
            }
            result = currentBase;
        } else if (signature.contains("List: java.lang.Object remove(int)>")) {
            HashSet<List> currentBase = SimulationUtil.getList(((InstanceInvokeExpr) expr).getBase(), currentValues);
            HashSet<Integer> currentArguments = SimulationUtil.getIntContent(expr.getArg(0), currentValues);
            HashSet<Object> returnResult = new HashSet<>();

            for (List list : currentBase) {
                for (Integer arg0 : currentArguments) {
                    returnResult.add(list.remove(arg0));
                }
            }
            if (!returnBase) {
                return returnResult;
            }
            result = currentBase;
        } else if (signature.contains("List: boolean remove(java.lang.Object)>")) {
            HashSet<List> currentBase = SimulationUtil.getList(((InstanceInvokeExpr) expr).getBase(), currentValues);
            HashSet<Integer> currentArguments = SimulationUtil.getIntContent(expr.getArg(0), currentValues);
            HashSet<Boolean> returnResult = new HashSet<>();

            for (List list : currentBase) {
                for (Integer arg0 : currentArguments) {
                    returnResult.add(list.remove(arg0));
                }
            }
            if (!returnBase) {
                return returnResult;
            }
            result = currentBase;
        } else if (signature.contains("List: boolean remove(java.util.Collection)>")) {
            HashSet<List> currentBase = SimulationUtil.getList(((InstanceInvokeExpr) expr).getBase(), currentValues);
            HashSet<Collection> currentArguments = SimulationUtil.getCollection(expr.getArg(0), currentValues);
            HashSet<Boolean> returnResult = new HashSet<>();

            for (List list : currentBase) {
                for (Collection arg0 : currentArguments) {
                    returnResult.add(list.remove(arg0));
                }
            }
            if (!returnBase) {
                return returnResult;
            }
            result = currentBase;
        } else if (signature.contains("List: java.lang.Object set(int,java.lang.Object)>")) {
            HashSet<List> currentBase = SimulationUtil.getList(((InstanceInvokeExpr) expr).getBase(), currentValues);
            HashSet<Integer> currentArg0 = SimulationUtil.getIntContent(expr.getArg(0), currentValues);
            HashSet<Object> currentArg1 = SimulationUtil.getObjectOrConstant(expr.getArg(1), currentValues);
            HashSet<Object> returnResult = new HashSet<>();

            for (List list : currentBase) {
                for (Integer arg0 : currentArg0) {
                    for (Object arg1 : currentArg1) {
                        try {
                            returnResult.add(list.set(arg0, arg1));
                        } catch (IndexOutOfBoundsException e) {
                            returnResult.add(list.add(arg1));
                        }
                    }
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
        if (rightValue.toString().contains("List:")) {
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
