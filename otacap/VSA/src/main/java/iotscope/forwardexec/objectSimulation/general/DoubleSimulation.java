package iotscope.forwardexec.objectSimulation.general;

import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.DoubleType;
import soot.Type;
import soot.Value;
import soot.jimple.*;

import java.util.HashMap;
import java.util.HashSet;

public class DoubleSimulation implements SimulationObjects {

    private static final Logger LOGGER = LoggerFactory.getLogger(DoubleSimulation.class);


    public DoubleSimulation() {
    }


    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        // :
        if (signature.equals("<java.lang.StringBuilder: java.lang.StringBuilder append(double)>") ){
            return transferValuesAndAppend(stmt, ((VirtualInvokeExpr) expr).getBase(), SimulationUtil.getStringContentFromDouble(expr.getArg(0), currentValues), currentValues);
        }
        return null;
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        // 
        if (signature.equals("<java.lang.StringBuilder: java.lang.StringBuilder append(double)>") ) {
            return transferValuesAndAppend(stmt, ((VirtualInvokeExpr) expr).getBase(), SimulationUtil.getStringContentFromDouble(expr.getArg(0), currentValues), currentValues);
        }
        return null;
    }

    @Override
    public HashSet<?> handleAssignNewExpression(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignConstant(AssignStmt stmt, Value rightValue, Value leftOp, HashMap<Value, HashSet<?>> currentValues) {
        if (rightValue instanceof DoubleConstant) {
            HashSet<Double> result = new HashSet<>();
            result.add(((DoubleConstant) rightValue).value);
            return result;
        }
        return null;
    }

    @Override
    public HashSet<?> handleAssignNewArrayExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        NewArrayExpr newArrayExpr = ((NewArrayExpr) rightValue);
        if (newArrayExpr.getBaseType().toString().equals("java.lang.Double") || newArrayExpr.getBaseType() instanceof DoubleType) {
            return SimulationUtil.initArray(0d, newArrayExpr, currentValues);
        }
        return null;
    }


    @Override
    public HashSet<?> handleAssignArithmeticExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        //Save cast because it is already checked in the simulation engine if it is a float binary operation expr
        Value op1 = ((BinopExpr) rightValue).getOp1();
        Value op2 = ((BinopExpr) rightValue).getOp2();
        Type type = ((BinopExpr) rightValue).getOp1().getType();

        if (!(type instanceof DoubleType)) {
            return null;
        }
        HashSet<Double> var1 = SimulationUtil.getDoubleContent(op1, currentValues);
        HashSet<Double> var2 = SimulationUtil.getDoubleContent(op2, currentValues);

        HashSet<Double> result = new HashSet<>();
        if (rightValue instanceof AddExpr) {
            var1.forEach(
                    v1 -> {
                        var2.forEach(v2 -> {
                            if (result.size() < 100) {
                                result.add(v1 + v2);
                            }
                        });
                    }
            );

        } else if (rightValue instanceof DivExpr) {
            var1.forEach(
                    v1 -> {
                        var2.forEach(v2 -> {
                            if (result.size() < 100) {
                                if (v2 != 0) {
                                    result.add(v1 / v2);
                                } else {
                                    result.add(v1);
                                }
                            }
                        });
                    }
            );
        } else if (rightValue instanceof MulExpr) {
            var1.forEach(
                    v1 -> {
                        var2.forEach(v2 -> {
                            if (result.size() < 100) {
                                result.add(v1 * v2);
                            }
                        });
                    }
            );
        } else if (rightValue instanceof RemExpr) {
            var1.forEach(
                    v1 -> {
                        var2.forEach(v2 -> {
                            if (result.size() < 100) {
                                if (v2 != 0) {
                                    result.add(v1 % v2);
                                } else {
                                    result.add(v1);
                                }
                            }
                        });
                    }
            );
        } else if (rightValue instanceof SubExpr) {
            var1.forEach(
                    v1 -> {
                        var2.forEach(v2 -> {
                            if (result.size() < 100) {
                                result.add(v1 - v2);
                            }
                        });
                    }
            );
        }


        return result;
    }

    private HashSet<String> transferValuesAndAppend(Stmt stmt, Value from, HashSet<String> appends, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<String> currentValuesFrom = SimulationUtil.getStringContent(from, currentValues);
        if (currentValuesFrom.size() == 0) {
            currentValuesFrom = new HashSet<>();
            currentValuesFrom.add("");
        }

        if (appends.size() == 0) {
            LOGGER.warn(String.format("[%s] [SIMULATE][transferValuesAndAppend arg unknown]: %s", this.hashCode(), stmt));
            appends = new HashSet<>();
            appends.add("");
        } 

        HashSet<String> newValues = new HashSet<>();
        for (String append : appends) {
            for (String str : currentValuesFrom) {
                if (append == null || str == null || newValues.size() >= 7000) {
                    continue;
                }
                if (append.startsWith("&") && str.contains(append)) {
                    LOGGER.debug("Do not append {}, because {} already contains it", append, str);
                    continue;
                }
                if (str.length() < 7000 && append.length() < 7000) {
                    newValues.add(str + append);
                } else if (append.length() < 7000) {
                    newValues.add(append);
                } else {
                    int min = Math.min(str.length(), 7000);
                    newValues.add(str.substring(0, min));
                }
            }
        }

        return (HashSet<String>) newValues.clone();
    }

}
