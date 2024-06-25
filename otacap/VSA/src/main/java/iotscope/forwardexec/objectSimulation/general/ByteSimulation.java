package iotscope.forwardexec.objectSimulation.general;

import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.ByteType;
import soot.Type;
import soot.Value;
import soot.jimple.*;

import java.util.HashMap;
import java.util.HashSet;

public class ByteSimulation implements SimulationObjects {

    private static final Logger LOGGER = LoggerFactory.getLogger(ByteSimulation.class);


    public ByteSimulation() {
    }


    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignNewExpression(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignConstant(AssignStmt stmt, Value rightValue, Value leftOp, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignNewArrayExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        NewArrayExpr newArrayExpr = ((NewArrayExpr) rightValue);
        if (newArrayExpr.getBaseType().toString().equals("byte") || newArrayExpr.getBaseType() instanceof ByteType) {
            return SimulationUtil.initArray(0, newArrayExpr, currentValues);
        }
        return null;
    }


    @Override
    public HashSet<?> handleAssignArithmeticExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        Value op1 = ((BinopExpr) rightValue).getOp1();
        Value op2 = ((BinopExpr) rightValue).getOp2();
        Type type = ((BinopExpr) rightValue).getOp1().getType();

        if (!(type instanceof ByteType)) {
            return null;
        }
        HashSet<Byte> var1 = SimulationUtil.getByteContent(op1, currentValues);
        HashSet<Byte> var2 = SimulationUtil.getByteContent(op2, currentValues);

        HashSet<Byte> result = new HashSet<>();
        if (rightValue instanceof AddExpr) {
            var1.forEach(
                    v1 -> {
                        var2.forEach(v2 -> {
                            if (result.size() < 100) {
                                result.add((byte) (v1 + v2));
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
                                    result.add((byte) (v1 / v2));
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
                                result.add((byte) (v1 * v2));
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
                                    result.add((byte) (v1 % v2));
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
                                result.add((byte) (v1 - v2));
                            }
                        });
                    }
            );
        } else if (rightValue instanceof AndExpr) {
            var1.forEach(
                    v1 -> {
                        var2.forEach(v2 -> {
                            if (result.size() < 100) {
                                result.add((byte) (v1 & v2));
                            }
                        });
                    }
            );
        } else if (rightValue instanceof OrExpr) {
            var1.forEach(
                    v1 -> {
                        var2.forEach(v2 -> {
                            if (result.size() < 100) {
                                result.add((byte) (v1 | v2));
                            }
                        });
                    }
            );
        } else if (rightValue instanceof ShlExpr) {
            var1.forEach(
                    v1 -> {
                        var2.forEach(v2 -> {
                            if (result.size() < 100) {
                                result.add((byte) (v1 << v2));
                            }
                        });
                    }
            );
        } else if (rightValue instanceof ShrExpr) {
            var1.forEach(
                    v1 -> {
                        var2.forEach(v2 -> {
                            if (result.size() < 100) {
                                result.add((byte) (v1 >> v2));
                            }
                        });
                    }
            );
        } else if (rightValue instanceof UshrExpr) {
            var1.forEach(
                    v1 -> {
                        var2.forEach(v2 -> {
                            if (result.size() < 100) {
                                result.add((byte) (v1 >>> v2));
                            }
                        });
                    }
            );
        } else if (rightValue instanceof XorExpr) {
            var1.forEach(
                    v1 -> {
                        var2.forEach(v2 -> {
                            if (result.size() < 100) {
                                result.add((byte) (v1 ^ v2));
                            }
                        });
                    }
            );
        }


        return result;
    }


}
