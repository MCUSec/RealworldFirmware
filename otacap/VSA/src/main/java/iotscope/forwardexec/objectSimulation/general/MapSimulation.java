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

public class MapSimulation implements SimulationObjects {

    private static final Logger LOGGER = LoggerFactory.getLogger(MapSimulation.class);


    public MapSimulation() {
    }


    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (!signature.contains("Map:")) {
            return null;
        }
        HashSet<HashMap> result = new HashSet<>();
        if (signature.equals("<java.util.HashMap: void <init>(java.util.Map)>") || signature.equals("<java.util.TreeMap: void <init>(java.util.Map)>") || signature.equals("<java.util.Map: void <init>(java.util.Map)>")) {
            HashSet<Map> currentArguments = SimulationUtil.getMap(expr.getArg(0), currentValues);
            currentArguments.forEach(x -> {
                if (x != null) {
                    result.add(new HashMap(x));
                } else {
                    result.add(new HashMap());
                }
            });
        } else if (signature.contains("Map: void <init>")) {
            result.add(new HashMap());
        } else if (signature.contains("Map: void putAll(java.lang.Map)>")) {
            HashSet<Map> currentBase = SimulationUtil.getMap(((InstanceInvokeExpr) expr).getBase(), currentValues);
            HashSet<Map> currentArg0 = SimulationUtil.getMap(expr.getArg(0), currentValues);
            for (Map map : currentBase) {
                for (Map o : currentArg0) {
                    map.putAll(o);
                }
            }
            return currentBase;
        } else if (signature.contains("Map: java.lang.Object put(java.lang.Object,java.lang.Object)>")) {
            HashSet<Map> currentBase = SimulationUtil.getMap(((InstanceInvokeExpr) expr).getBase(), currentValues);
            HashSet<Object> currentArg0 = SimulationUtil.getObjectOrConstant(expr.getArg(0), currentValues);
            List<Object> currentArg1 = Arrays.asList(SimulationUtil.getObjectOrConstant(expr.getArg(1), currentValues).toArray());
            if (currentArg1.size() == 0) {
                currentArg1 = new ArrayList<>();
            }
            while (currentArg1.size() < currentArg0.size()) {
                try {
                    currentArg1.add("");
                } catch (UnsupportedOperationException e) {
                    LOGGER.error("Could not align array argument: {}", e.getLocalizedMessage());
                    break;
                }
            }
            for (Map map : currentBase) {
                for (Object arg0 : currentArg0) {
                    for (Object arg1 : currentArg1) {
                        map.put(arg0, arg1);
                    }
                }
            }
            return currentBase;
        } else if (signature.contains("Map: java.lang.Object replace(java.lang.Object,java.lang.Object)>")) {
            HashSet<Map> currentBase = SimulationUtil.getMap(((InstanceInvokeExpr) expr).getBase(), currentValues);
            HashSet<Object> currentArg0 = SimulationUtil.getObjectOrConstant(expr.getArg(0), currentValues);
            List<Object> currentArg1 = Arrays.asList(SimulationUtil.getObjectOrConstant(expr.getArg(1), currentValues).toArray());
            if (currentArg1.size() == 0) {
                currentArg1 = new ArrayList<>();
            }
            while (currentArg1.size() < currentArg0.size()) {
                try {
                    currentArg1.add("");
                } catch (UnsupportedOperationException e) {
                    LOGGER.error("Could not align array argument: {}", e.getLocalizedMessage());
                    break;
                }            }
            for (Map map : currentBase) {
                for (Object arg0 : currentArg0) {
                    for (Object arg1 : currentArg1) {
                        map.replace(arg0, arg1);
                    }
                }
            }
            return currentBase;

        }
        return result.size() == 0 ? null : result;
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (!signature.contains("Map:")) {
            return null;
        }
        HashSet<Object> result = new HashSet<>();
        if (signature.contains("Map: java.lang.Object get(java.lang.Object)")) {
            HashSet<Map> currentBase = SimulationUtil.getMap(((InstanceInvokeExpr) expr).getBase(), currentValues);
            HashSet<Object> currentArg0 = SimulationUtil.getObjectOrConstant(expr.getArg(0), currentValues);
            for (Map map : currentBase) {
                for (Object o : currentArg0) {
                    result.add(map.get(o));
                }
            }
        } else if (signature.contains("Map: java.lang.Object getOrDefault(java.lang.Object,java.lang.Object)>")) {
            HashSet<Map> currentBase = SimulationUtil.getMap(((InstanceInvokeExpr) expr).getBase(), currentValues);
            HashSet<Object> currentArg0 = SimulationUtil.getObjectOrConstant(expr.getArg(0), currentValues);
            HashSet<Object> currentArg1 = SimulationUtil.getObjectOrConstant(expr.getArg(1), currentValues);
            for (Map map : currentBase) {
                for (Object o : currentArg0) {
                    Object getResult = map.get(o);
                    if (getResult == null) {
                        result.addAll(currentArg1);
                    } else {
                        result.add(getResult);
                    }
                }
            }
        } else if (signature.contains("Map: java.lang.Object put(java.lang.Object,java.lang.Object)>")) {
            HashSet<Map> currentBase = SimulationUtil.getMap(((InstanceInvokeExpr) expr).getBase(), currentValues);
            HashSet<Object> currentArg0 = SimulationUtil.getObjectOrConstant(expr.getArg(0), currentValues);
            List<Object> currentArg1 = Arrays.asList(SimulationUtil.getObjectOrConstant(expr.getArg(1), currentValues).toArray());
            if (currentArg1.size() == 0) {
                currentArg1 = new ArrayList<>();
            }
            while (currentArg1.size() < currentArg0.size()) {
                try {
                    currentArg1.add("");
                } catch (UnsupportedOperationException e) {
                    LOGGER.error("Could not align array argument: {}", e.getLocalizedMessage());
                    break;

                }
            }
            for (Map map : currentBase) {
                for (Object arg0 : currentArg0) {
                    for (Object arg1 : currentArg1) {
                        result.add(map.put(arg0, arg1));
                    }
                }
            }
        } else if (signature.contains("Map: java.lang.Object replace(java.lang.Object,java.lang.Object)>")) {
            HashSet<Map> currentBase = SimulationUtil.getMap(((InstanceInvokeExpr) expr).getBase(), currentValues);
            HashSet<Object> currentArg0 = SimulationUtil.getObjectOrConstant(expr.getArg(0), currentValues);
            List<Object> currentArg1 = Arrays.asList(SimulationUtil.getObjectOrConstant(expr.getArg(1), currentValues).toArray());
            if (currentArg1.size() == 0) {
                currentArg1 = new ArrayList<>();
            }
            while (currentArg1.size() < currentArg0.size()) {
                try {
                    currentArg1.add("");
                } catch (UnsupportedOperationException e) {
                    LOGGER.error("Could not align array argument: {}", e.getLocalizedMessage());
                    break;

                }
            }
            for (Map map : currentBase) {
                for (Object arg0 : currentArg0) {
                    for (Object arg1 : currentArg1) {
                        result.add(map.replace(arg0, arg1));
                    }
                }
            }

        } else if (signature.contains("Map: boolean replace(java.lang.Object,java.lang.Object,java.lang.Object)>")) {
            HashSet<Map> currentBase = SimulationUtil.getMap(((InstanceInvokeExpr) expr).getBase(), currentValues);
            HashSet<Object> currentArg0 = SimulationUtil.getObjectOrConstant(expr.getArg(0), currentValues);
            List<Object> currentArg1 = Arrays.asList(SimulationUtil.getObjectOrConstant(expr.getArg(2), currentValues));
            if (currentArg1.size() == 0) {
                currentArg1 = new ArrayList<>();
            }
            while (currentArg1.size() < currentArg0.size()) {
                try {
                    currentArg1.add("");
                } catch (UnsupportedOperationException e) {
                    LOGGER.error("Could not align array argument: {}", e.getLocalizedMessage());
                    break;
                }
            }
            HashSet<Boolean> results = new HashSet<>();
            for (Map map : currentBase) {
                for (Object arg0 : currentArg0) {
                    for (Object arg2 : currentArg1) {
                        map.replace(arg0, arg2);
                        results.add(true);
                    }

                }
            }

            return results;
        }
        return result.size() == 0 ? null : result;
    }

    @Override
    public HashSet<?> handleAssignNewExpression(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        if (rightValue.toString().contains("Map:")) {
            System.out.println("got a Map to handle");
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
